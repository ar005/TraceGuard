package com.traceguard.agent.android.monitor

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.config.AgentConfig
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.PackageEntry
import com.traceguard.agent.events.PkgInventoryPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class VulnMonitor(
    private val context: Context,
    private val config:  AgentConfig,
) : Monitor {
    override val name = "VulnMonitor"

    private var job: kotlinx.coroutines.Job? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        job = scope.launch {
            while (isActive) {
                emit(buildInventoryEvent())
                delay(config.vulnScanIntervalHours * 3_600_000L)
            }
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
    }

    @Suppress("DEPRECATION")
    private fun buildInventoryEvent(): EventEnvelope {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PackageManager.PackageInfoFlags.of(0)
        } else {
            0
        }
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(flags)
        } else {
            pm.getInstalledPackages(0)
        }

        val entries = packages.map { info ->
            PackageEntry(
                packageName = info.packageName,
                appName     = runCatching {
                    pm.getApplicationLabel(info.applicationInfo!!).toString()
                }.getOrDefault(info.packageName),
                versionName = info.versionName ?: "",
                versionCode = info.longVersionCode,
                isSystemApp = (info.applicationInfo?.flags
                    ?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0,
                installedAt = info.firstInstallTime,
            )
        }

        val payload = PkgInventoryPayload(
            os          = "android",
            osVersion   = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            packages    = entries,
            totalCount  = entries.size,
        )
        return buildEnvelope(EventTypes.PKG_INVENTORY, Json.encodeToString(payload))
    }
}
