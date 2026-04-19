package com.traceguard.agent.android.monitor

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.NetConnectPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class NetworkMonitor(private val context: Context) : Monitor {
    override val name = "NetworkMonitor"

    private var callback: ConnectivityManager.NetworkCallback? = null
    private val cm get() = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scope.launch { emit(buildEvent(network, connected = true)) }
            }

            override fun onLost(network: Network) {
                scope.launch { emit(buildEvent(network, connected = false)) }
            }
        }
        cm.registerNetworkCallback(
            NetworkRequest.Builder().build(),
            callback!!
        )
    }

    override fun stop() {
        callback?.let { cm.unregisterNetworkCallback(it) }
        callback = null
    }

    private fun buildEvent(network: Network, connected: Boolean): EventEnvelope {
        val caps = cm.getNetworkCapabilities(network)
        val type = when {
            caps == null                                                -> "NONE"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)      -> "WIFI"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)  -> "CELLULAR"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)  -> "ETHERNET"
            else                                                        -> "OTHER"
        }
        val payload = NetConnectPayload(
            type        = type,
            isConnected = connected,
            capabilities = caps?.toString(),
        )
        val eventType = if (connected) EventTypes.NET_CONNECT else EventTypes.NET_DISCONNECT
        return buildEnvelope(eventType, Json.encodeToString(payload))
    }
}
