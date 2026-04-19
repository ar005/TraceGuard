package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.PowerPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class BatteryMonitor(private val context: Context) : Monitor {
    override val name = "BatteryMonitor"

    private var receiver: BroadcastReceiver? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val action = when (intent.action) {
                    Intent.ACTION_BATTERY_LOW        -> "BATTERY_LOW"
                    Intent.ACTION_BATTERY_OKAY       -> "BATTERY_OKAY"
                    Intent.ACTION_POWER_CONNECTED    -> "POWER_CONNECTED"
                    Intent.ACTION_POWER_DISCONNECTED -> "POWER_DISCONNECTED"
                    else                             -> return
                }
                val pct       = batteryPct()
                val charging  = isCharging()
                val payload   = Json.encodeToString(
                    PowerPayload(action = action, batteryPct = pct, isCharging = charging)
                )
                scope.launch { emit(buildEnvelope(EventTypes.POWER_EVENT, payload)) }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_BATTERY_LOW)
            addAction(Intent.ACTION_BATTERY_OKAY)
            addAction(Intent.ACTION_POWER_CONNECTED)
            addAction(Intent.ACTION_POWER_DISCONNECTED)
        }
        context.registerReceiver(receiver, filter)
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    private fun batteryPct(): Int {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?: return -1
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        return if (level >= 0 && scale > 0) (level * 100 / scale) else -1
    }

    private fun isCharging(): Boolean {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?: return false
        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        return status == BatteryManager.BATTERY_STATUS_CHARGING ||
               status == BatteryManager.BATTERY_STATUS_FULL
    }
}
