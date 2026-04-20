package com.traceguard.agent.android.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.events.AppInstallPayload
import com.traceguard.agent.events.AppRemovePayload
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class AppInstallMonitor(private val context: Context) : Monitor {
    override val name = "AppInstallMonitor"

    private var receiver: BroadcastReceiver? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                scope.launch {
                    when (intent.action) {
                        Intent.ACTION_PACKAGE_ADDED    -> emitInstall(pkg, emit)
                        Intent.ACTION_PACKAGE_REMOVED  -> emitRemove(pkg, emit)
                        Intent.ACTION_PACKAGE_REPLACED -> emitUpdate(pkg, emit)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        context.registerReceiver(receiver, filter)
    }

    override fun stop() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    private suspend fun emitInstall(pkg: String, emit: suspend (EventEnvelope) -> Unit) {
        val info = getPackageInfo(pkg) ?: return
        val payload = AppInstallPayload(
            packageName      = pkg,
            appName          = getAppName(info),
            versionName      = info.versionName ?: "",
            versionCode      = info.longVersionCode,
            installer        = getInstallerPackage(pkg),
            permissions      = info.requestedPermissions?.toList() ?: emptyList(),
            isSystemApp      = isSystemApp(info),
            apkPath          = info.applicationInfo?.sourceDir,
            firstInstallTime = info.firstInstallTime,
        )
        emit(buildEnvelope(EventTypes.APP_INSTALL, Json.encodeToString(payload)))
    }

    private suspend fun emitRemove(pkg: String, emit: suspend (EventEnvelope) -> Unit) {
        val payload = AppRemovePayload(
            packageName = pkg,
            appName     = pkg,
            versionName = "",
            versionCode = 0,
        )
        emit(buildEnvelope(EventTypes.APP_REMOVE, Json.encodeToString(payload)))
    }

    private suspend fun emitUpdate(pkg: String, emit: suspend (EventEnvelope) -> Unit) {
        val info = getPackageInfo(pkg) ?: return
        val payload = AppInstallPayload(
            packageName      = pkg,
            appName          = getAppName(info),
            versionName      = info.versionName ?: "",
            versionCode      = info.longVersionCode,
            installer        = getInstallerPackage(pkg),
            permissions      = info.requestedPermissions?.toList() ?: emptyList(),
            isSystemApp      = isSystemApp(info),
            apkPath          = info.applicationInfo?.sourceDir,
            firstInstallTime = info.firstInstallTime,
        )
        emit(buildEnvelope(EventTypes.APP_UPDATE, Json.encodeToString(payload)))
    }

    @Suppress("DEPRECATION")
    private fun getPackageInfo(pkg: String): PackageInfo? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(
                PackageManager.GET_PERMISSIONS.toLong()
            ))
        } else {
            context.packageManager.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
        }
    }.getOrNull()

    private fun getAppName(info: PackageInfo): String =
        context.packageManager.getApplicationLabel(info.applicationInfo!!).toString()

    private fun getInstallerPackage(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private fun isSystemApp(info: PackageInfo): Boolean {
        val flags = info.applicationInfo?.flags ?: return false
        return (flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
    }
}
