package com.traceguard.agent.android.service

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileInputStream

/**
 * VPN-based containment: routes all device traffic through a local TUN interface
 * and silently discards it, severing network access for every app except this one
 * (excluded via addDisallowedApplication so the backend gRPC stream stays alive).
 *
 * Triggered by live response commands `isolate` / `release` from the analyst console.
 * Requires VPN permission pre-authorised via VpnService.prepare() from the UI.
 */
class ContainmentVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var drainJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_ISOLATE -> isolate()
            ACTION_RELEASE -> release()
        }
        return START_NOT_STICKY
    }

    private fun isolate() {
        vpnInterface?.close()
        drainJob?.cancel()

        val builder = Builder()
            .setSession("TraceGuard Containment")
            .addAddress("10.99.0.1", 32)       // TUN IPv4 address
            .addAddress("fdca:ffee::1", 128)   // TUN IPv6 address (needed before addRoute("::",0))
            .addRoute("0.0.0.0", 0)            // capture all IPv4
            .addRoute("::", 0)                  // capture all IPv6
            .setMtu(1500)
            .setBlocking(false)

        // Exempt our own process so the backend gRPC stream survives containment
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

        val iface = builder.establish()
        if (iface == null) {
            // VPN permission not yet granted — user must approve from the UI first
            _state.value = ContainmentState.PERMISSION_REQUIRED
            stopSelf()
            return
        }

        vpnInterface = iface
        _state.value = ContainmentState.ISOLATED

        // Drain loop: read packets off the TUN fd and discard them.
        // Other apps' traffic enters the TUN but never exits — effective blackhole.
        drainJob = scope.launch {
            val stream = FileInputStream(iface.fileDescriptor)
            val buf = ByteArray(32_767)
            while (isActive && vpnInterface != null) {
                try {
                    stream.read(buf)
                } catch (_: Exception) {
                    break
                }
            }
        }
    }

    private fun release() {
        drainJob?.cancel()
        drainJob = null
        vpnInterface?.close()
        vpnInterface = null
        _state.value = ContainmentState.RELEASED
        stopSelf()
    }

    override fun onDestroy() {
        scope.cancel()
        vpnInterface?.close()
        if (_state.value == ContainmentState.ISOLATED) {
            _state.value = ContainmentState.RELEASED
        }
        super.onDestroy()
    }

    companion object {
        const val ACTION_ISOLATE = "com.traceguard.ISOLATE"
        const val ACTION_RELEASE = "com.traceguard.RELEASE"

        private val _state = MutableStateFlow(ContainmentState.RELEASED)

        /** Shared observable containment state — observed by UI and ViewModel. */
        val state: StateFlow<ContainmentState> = _state.asStateFlow()
    }
}

enum class ContainmentState { RELEASED, ISOLATED, PERMISSION_REQUIRED }
