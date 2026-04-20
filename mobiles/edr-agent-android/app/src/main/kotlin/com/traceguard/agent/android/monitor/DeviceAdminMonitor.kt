package com.traceguard.agent.android.monitor

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.DeviceAdminPayload
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

// System device admin packages that are expected on most devices.
private val KNOWN_ADMINS = setOf(
    "com.android.enterprise.owned",
    "com.android.managedprovisioning",
    "com.samsung.android.knox.containeragent",
    "com.google.android.apps.work.clouddpc",
)

class DeviceAdminMonitor(private val context: Context) : Monitor {
    override val name = "DeviceAdminMonitor"

    private val dpm     = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val current = mutableSetOf<String>() // currently active admin component flat strings
    private var job: kotlinx.coroutines.Job? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        // Seed without emitting
        current += activeAdmins()

        job = scope.launch {
            while (isActive) {
                delay(30_000)
                checkAdmins(emit)
            }
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun checkAdmins(emit: suspend (EventEnvelope) -> Unit) {
        val now = activeAdmins()
        val added   = now - current
        val removed = current - now
        current.clear()
        current += now

        for (flat in added) {
            val pkg = flat.substringBefore("/")
            emit(event(pkg, "enabled"))
        }
        for (flat in removed) {
            val pkg = flat.substringBefore("/")
            emit(event(pkg, "disabled"))
        }
    }

    private fun activeAdmins(): Set<String> =
        dpm.activeAdmins?.map { it.flattenToString() }?.toSet() ?: emptySet()

    private fun event(pkg: String, action: String): EventEnvelope {
        val appName = runCatching {
            context.packageManager
                .getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0))
                .toString()
        }.getOrDefault(pkg)

        val payload = DeviceAdminPayload(
            packageName  = pkg,
            appName      = appName,
            action       = action,
            isKnownAdmin = pkg in KNOWN_ADMINS,
        )
        return buildEnvelope(EventTypes.DEVICE_ADMIN_CHANGE, Json.encodeToString(payload))
    }
}
