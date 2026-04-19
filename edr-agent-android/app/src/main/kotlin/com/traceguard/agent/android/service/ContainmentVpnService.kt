package com.traceguard.agent.android.service

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Phase 2 — full VPN-based containment (block all traffic except backend).
 * Currently a stub that establishes but passes all traffic through.
 */
class ContainmentVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_ISOLATE -> isolate()
            ACTION_RELEASE -> release()
        }
        return START_NOT_STICKY
    }

    private fun isolate() {
        // Phase 2: configure Builder with routes that drop all traffic
        // except the backend host. For now, this is a no-op stub.
    }

    private fun release() {
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        vpnInterface?.close()
        super.onDestroy()
    }

    companion object {
        const val ACTION_ISOLATE = "com.traceguard.ISOLATE"
        const val ACTION_RELEASE = "com.traceguard.RELEASE"
    }
}
