package com.traceguard.agent.android.monitor

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.AccessibilityServicePayload
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

// System accessibility services that are expected on most devices.
private val KNOWN_SERVICES = setOf(
    "com.google.android.marvin.talkback",
    "com.android.talkback",
    "com.samsung.android.accessibility.universalswitch",
    "com.android.systemui",
    "com.android.accessibility.framework",
    "com.google.android.accessibility.switchaccess",
    "com.android.settings",
)

class AccessibilityMonitor(private val context: Context) : Monitor {
    override val name = "AccessibilityMonitor"

    private val am      = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    private val current = mutableSetOf<String>() // currently enabled service component flat strings
    private var job: kotlinx.coroutines.Job? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        current += enabledServiceIds()
        job = scope.launch {
            while (isActive) {
                delay(30_000)
                checkServices(emit)
            }
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun checkServices(emit: suspend (EventEnvelope) -> Unit) {
        val now     = enabledServiceIds()
        val enabled  = now - current
        val disabled = current - now
        current.clear()
        current += now

        for (flat in enabled)  emit(event(flat, "ENABLED"))
        for (flat in disabled) emit(event(flat, "DISABLED"))
    }

    private fun enabledServiceIds(): Set<String> =
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { it.resolveInfo?.serviceInfo?.let { si -> "${si.packageName}/${si.name}" } }
            .toSet()

    private fun event(flat: String, action: String): EventEnvelope {
        val pkg         = flat.substringBefore("/")
        val serviceName = flat.substringAfter("/")
        val isKnown     = KNOWN_SERVICES.any { flat.startsWith(it) }

        val payload = AccessibilityServicePayload(
            packageName    = pkg,
            serviceName    = serviceName,
            action         = action,
            isKnownService = isKnown,
        )
        return buildEnvelope(EventTypes.ACCESSIBILITY_SERVICE, Json.encodeToString(payload))
    }
}
