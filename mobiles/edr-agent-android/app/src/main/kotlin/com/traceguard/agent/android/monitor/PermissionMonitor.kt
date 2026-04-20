package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.PermChangePayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

// Dangerous permissions worth tracking — covers privacy, finance, comms, and device control.
private val DANGEROUS_PERMISSIONS = setOf(
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
)

class PermissionMonitor(private val context: Context) : Monitor {
    override val name = "PermissionMonitor"

    // packageName → set of currently granted dangerous permissions
    private val snapshot = mutableMapOf<String, Set<String>>()
    private var receiver: BroadcastReceiver? = null
    private var pollJob: kotlinx.coroutines.Job? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        // Seed the initial snapshot silently
        buildSnapshot()

        // Listen for package changes (permission grant/revoke fires ACTION_PACKAGE_CHANGED)
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                scope.launch { diffPackage(pkg, emit) }
            }
        }
        val filter = IntentFilter(Intent.ACTION_PACKAGE_CHANGED).apply { addDataScheme("package") }
        context.registerReceiver(receiver, filter)

        // Also poll every 60 s to catch changes missed during receiver downtime
        pollJob = scope.launch {
            while (isActive) {
                delay(60_000)
                diffAll(emit)
            }
        }
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
        pollJob?.cancel()
        pollJob = null
    }

    private fun buildSnapshot() {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        for (info in packages) {
            snapshot[info.packageName] = grantedDangerous(info)
        }
    }

    private suspend fun diffPackage(pkg: String, emit: suspend (EventEnvelope) -> Unit) {
        val info = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
            }
        }.getOrNull() ?: run {
            snapshot.remove(pkg)
            return
        }

        val before  = snapshot[pkg] ?: emptySet()
        val after   = grantedDangerous(info)
        val granted = after - before
        val revoked = before - after
        snapshot[pkg] = after

        val appName = runCatching {
            context.packageManager.getApplicationLabel(info.applicationInfo!!).toString()
        }.getOrDefault(pkg)

        for (perm in granted) {
            emit(buildEnvelope(EventTypes.PERM_GRANT, Json.encodeToString(
                PermChangePayload(packageName = pkg, appName = appName, permission = perm, action = "GRANT")
            )))
        }
        for (perm in revoked) {
            emit(buildEnvelope(EventTypes.PERM_REVOKE, Json.encodeToString(
                PermChangePayload(packageName = pkg, appName = appName, permission = perm, action = "REVOKE")
            )))
        }
    }

    private suspend fun diffAll(emit: suspend (EventEnvelope) -> Unit) {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        for (info in packages) {
            diffPackage(info.packageName, emit)
        }
    }

    private fun grantedDangerous(info: android.content.pm.PackageInfo): Set<String> {
        val perms  = info.requestedPermissions ?: return emptySet()
        val flags  = info.requestedPermissionsFlags ?: return emptySet()
        return perms.indices
            .filter { i ->
                perms[i] in DANGEROUS_PERMISSIONS &&
                (flags[i] and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            }
            .map { perms[it] }
            .toSet()
    }
}
