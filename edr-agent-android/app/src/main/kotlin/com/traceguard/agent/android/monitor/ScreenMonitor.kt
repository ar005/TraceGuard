package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.ScreenPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ScreenMonitor(private val context: Context) : Monitor {
    override val name = "ScreenMonitor"

    private var receiver: BroadcastReceiver? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val action = when (intent.action) {
                    Intent.ACTION_SCREEN_ON    -> "ON"
                    Intent.ACTION_SCREEN_OFF   -> "OFF"
                    Intent.ACTION_USER_PRESENT -> "UNLOCKED"
                    else                       -> return
                }
                val payload = Json.encodeToString(ScreenPayload(action = action))
                scope.launch { emit(buildEnvelope(EventTypes.SCREEN_EVENT, payload)) }
            }
        }
        // Screen intents cannot be declared in the manifest — must register dynamically.
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        context.registerReceiver(receiver, filter)
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }
}
