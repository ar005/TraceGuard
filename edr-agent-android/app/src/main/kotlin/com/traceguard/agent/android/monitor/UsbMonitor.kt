package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.provider.Settings
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.UsbDevicePayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class UsbMonitor(private val context: Context) : Monitor {
    override val name = "UsbMonitor"

    private var receiver: BroadcastReceiver? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val attached = intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED
                val device   = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                }
                val payload = UsbDevicePayload(
                    action       = if (attached) "ATTACHED" else "DETACHED",
                    deviceName   = device?.deviceName,
                    vendorId     = device?.vendorId ?: -1,
                    productId    = device?.productId ?: -1,
                    debugEnabled = adbEnabled(),
                )
                scope.launch {
                    emit(buildEnvelope(EventTypes.USB_DEVICE, Json.encodeToString(payload)))
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        context.registerReceiver(receiver, filter)
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    private fun adbEnabled(): Boolean = runCatching {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    }.getOrDefault(false)
}
