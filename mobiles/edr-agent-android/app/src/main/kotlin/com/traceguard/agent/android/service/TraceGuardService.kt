package com.traceguard.agent.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.traceguard.agent.agent.AgentCore
import com.traceguard.agent.android.config.ConfigRepository
import com.traceguard.agent.android.liveresponse.LiveResponseHandler
import com.traceguard.agent.android.monitor.AccessibilityMonitor
import com.traceguard.agent.android.monitor.AppInstallMonitor
import com.traceguard.agent.android.monitor.BatteryMonitor
import com.traceguard.agent.android.monitor.DeviceAdminMonitor
import com.traceguard.agent.android.monitor.NetworkMonitor
import com.traceguard.agent.android.monitor.PermissionMonitor
import com.traceguard.agent.android.monitor.ProcessMonitor
import com.traceguard.agent.android.monitor.ScreenMonitor
import com.traceguard.agent.android.monitor.UsbMonitor
import com.traceguard.agent.android.monitor.VulnMonitor
import com.traceguard.agent.android.monitor.WifiMonitor
import com.traceguard.agent.android.transport.GrpcTransport
import com.traceguard.agent.android.R
import com.traceguard.agent.android.ui.MainActivity
import com.traceguard.agent.android.util.initEventBuilder
import com.traceguard.agent.buffer.EventBuffer
import com.traceguard.agent.config.AgentConfig
import com.traceguard.agent.proto.LiveResult as ProtoLiveResult
import dagger.hilt.android.AndroidEntryPoint
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.net.Inet4Address
import java.net.NetworkInterface
import javax.inject.Inject

@AndroidEntryPoint
class TraceGuardService : LifecycleService() {

    @Inject lateinit var config:    AgentConfig
    @Inject lateinit var transport: GrpcTransport
    @Inject lateinit var buffer:    EventBuffer
    @Inject lateinit var cfgRepo:   ConfigRepository

    private lateinit var agentCore:           AgentCore
    private lateinit var liveResponseHandler: LiveResponseHandler

    companion object {
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID      = "tg_service"

        fun start(context: Context) = ContextCompat.startForegroundService(
            context, Intent(context, TraceGuardService::class.java)
        )

        fun stop(context: Context) =
            context.stopService(Intent(context, TraceGuardService::class.java))
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting…"))

        val hostname = "${Build.BRAND}-${Build.MODEL}".replace(" ", "_")
        initEventBuilder(config.agentId, hostname)

        liveResponseHandler = LiveResponseHandler(applicationContext)

        agentCore = AgentCore(
            config    = config,
            transport = transport,
            buffer    = buffer,
            monitors  = listOf(
                // Phase 1
                AppInstallMonitor(applicationContext),
                NetworkMonitor(applicationContext),
                VulnMonitor(applicationContext, config),
                // Phase 2
                PermissionMonitor(applicationContext),
                DeviceAdminMonitor(applicationContext),
                ScreenMonitor(applicationContext),
                UsbMonitor(applicationContext),
                WifiMonitor(applicationContext),
                AccessibilityMonitor(applicationContext),
                BatteryMonitor(applicationContext),
                ProcessMonitor(applicationContext, config),
            ),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        lifecycleScope.launch { initAgent() }
        return START_STICKY
    }

    override fun onDestroy() {
        agentCore.stop()
        super.onDestroy()
    }

    // ── Agent initialisation ─────────────────────────────────────────────────

    private suspend fun initAgent() {
        updateNotification("Connecting to backend…")

        transport.connect().onFailure {
            updateNotification("Backend unreachable — retrying…")
            delay(10_000)
            lifecycleScope.launch { initAgent() }
            return
        }

        val hostname  = "${Build.BRAND}-${Build.MODEL}".replace(" ", "_")
        val ip        = localIp()
        val osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"

        transport.register(hostname, ip, osVersion).onSuccess { assignedId ->
            agentCore.registration.onRegistered(assignedId, "")
            // Persist the assigned ID so it survives restarts
            cfgRepo.save(config.copy(agentId = agentCore.registration.agentId()))
            initEventBuilder(agentCore.registration.agentId(), hostname)
            updateNotification("Monitoring active  •  ${agentCore.registration.agentId()}")
        }.onFailure {
            updateNotification("Registration failed — retrying…")
            delay(15_000)
            lifecycleScope.launch { initAgent() }
            return
        }

        agentCore.start()
        startHeartbeatLoop()
        startLiveResponseLoop()
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    private fun startHeartbeatLoop() {
        lifecycleScope.launch(Dispatchers.IO) {
            val hostname = "${Build.BRAND}-${Build.MODEL}".replace(" ", "_")
            while (isActive) {
                delay(config.heartbeatIntervalSeconds * 1_000L)
                val stats = agentCore.heartbeatTracker.snapshot(buffer.count())
                transport.heartbeat(hostname, stats).onSuccess { configVer ->
                    if (configVer.isNotBlank() &&
                        configVer != agentCore.registration.configVersion()
                    ) {
                        // Config version bumped — could trigger hot-reload in Phase 2
                    }
                }
            }
        }
    }

    // ── Live response ─────────────────────────────────────────────────────────

    private fun startLiveResponseLoop() {
        lifecycleScope.launch(Dispatchers.IO) {
            while (isActive) {
                runCatching {
                    val resultChannel = Channel<ProtoLiveResult>(Channel.BUFFERED)
                    transport.openLiveResponse(resultChannel) { cmd ->
                        liveResponseHandler.handle(cmd).also {
                            // Populate agentId on the result
                        }.let { r ->
                            r.copy(agentId = agentCore.registration.agentId())
                        }
                    }
                }.onFailure {
                    delay(5_000)
                }
            }
        }
    }

    // ── Notification helpers ──────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = getString(R.string.notification_channel_desc) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(status: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TraceGuard EDR")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) =
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(status))

    private fun localIp(): String = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { !it.isLoopbackAddress && it is Inet4Address }
            ?.hostAddress
    }.getOrNull() ?: "unknown"
}

