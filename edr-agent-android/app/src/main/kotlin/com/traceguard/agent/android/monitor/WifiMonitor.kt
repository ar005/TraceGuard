package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.NetworkInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.WifiPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class WifiMonitor(private val context: Context) : Monitor {
    override val name = "WifiMonitor"

    private var receiver: BroadcastReceiver? = null
    private var lastSsid: String? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        receiver = object : BroadcastReceiver() {
            @Suppress("DEPRECATION")
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action != WifiManager.NETWORK_STATE_CHANGED_ACTION) return

                val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO, NetworkInfo::class.java)
                } else {
                    intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO)
                } ?: return

                val wm   = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val conn = wm.connectionInfo

                // SSID is "<unknown ssid>" when location permission is missing — treat as null
                val ssid = conn.ssid
                    ?.takeIf { it != "<unknown ssid>" && it.isNotBlank() }
                    ?.removeSurrounding("\"")

                when (info.state) {
                    NetworkInfo.State.CONNECTED -> {
                        if (ssid == lastSsid) return  // already reported
                        lastSsid = ssid
                        val payload = WifiPayload(
                            action   = "CONNECT",
                            ssid     = ssid,
                            bssid    = conn.bssid,
                            security = securityType(conn.networkId, wm),
                        )
                        scope.launch {
                            emit(buildEnvelope(EventTypes.WIFI_CONNECT, Json.encodeToString(payload)))
                        }
                    }
                    NetworkInfo.State.DISCONNECTED -> {
                        lastSsid = null
                        val payload = WifiPayload(action = "DISCONNECT", ssid = null, bssid = null, security = null)
                        scope.launch {
                            emit(buildEnvelope(EventTypes.WIFI_DISCONNECT, Json.encodeToString(payload)))
                        }
                    }
                    else -> Unit
                }
            }
        }
        context.registerReceiver(receiver, IntentFilter(WifiManager.NETWORK_STATE_CHANGED_ACTION))
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    @Suppress("DEPRECATION")
    private fun securityType(networkId: Int, wm: WifiManager): String? = runCatching {
        wm.configuredNetworks
            ?.firstOrNull { it.networkId == networkId }
            ?.let { cfg ->
                when {
                    cfg.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_PSK)  -> "WPA-PSK"
                    cfg.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_EAP)  -> "WPA-EAP"
                    cfg.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.NONE)     -> "OPEN"
                    else -> "UNKNOWN"
                }
            }
    }.getOrNull()
}
