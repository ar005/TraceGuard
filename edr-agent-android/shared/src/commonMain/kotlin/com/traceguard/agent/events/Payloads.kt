package com.traceguard.agent.events

import kotlinx.serialization.Serializable

@Serializable
data class AppInstallPayload(
    val packageName:      String,
    val appName:          String,
    val versionName:      String,
    val versionCode:      Long,
    val installer:        String?,
    val permissions:      List<String>,
    val isSystemApp:      Boolean,
    val apkPath:          String?,
    val firstInstallTime: Long,
)

@Serializable
data class AppRemovePayload(
    val packageName: String,
    val appName:     String,
    val versionName: String,
    val versionCode: Long,
)

@Serializable
data class NetConnectPayload(
    val type:         String,         // WIFI, CELLULAR, ETHERNET, NONE
    val isConnected:  Boolean,
    val ssid:         String? = null,
    val capabilities: String? = null,
)

@Serializable
data class PermChangePayload(
    val packageName: String,
    val appName:     String,
    val permission:  String,
    val action:      String,  // GRANT or REVOKE
)

@Serializable
data class DeviceAdminPayload(
    val packageName:  String,
    val appName:      String,
    val action:       String,   // enabled or disabled
    val isKnownAdmin: Boolean,
)

@Serializable
data class ScreenPayload(
    val action: String,   // ON, OFF, UNLOCKED
)

@Serializable
data class UsbDevicePayload(
    val action:       String,    // ATTACHED or DETACHED
    val deviceName:   String?,
    val vendorId:     Int,
    val productId:    Int,
    val debugEnabled: Boolean = false,
)

@Serializable
data class WifiPayload(
    val action:   String,   // CONNECT or DISCONNECT
    val ssid:     String?,
    val bssid:    String?,
    val security: String?,
)

@Serializable
data class AccessibilityServicePayload(
    val packageName:    String,
    val serviceName:    String,
    val action:         String,   // ENABLED or DISABLED
    val isKnownService: Boolean,
)

@Serializable
data class PowerPayload(
    val action:     String,   // BATTERY_LOW, POWER_CONNECTED, POWER_DISCONNECTED
    val batteryPct: Int,
    val isCharging: Boolean,
)

@Serializable
data class PackageEntry(
    val packageName: String,
    val appName:     String,
    val versionName: String,
    val versionCode: Long,
    val isSystemApp: Boolean,
    val installedAt: Long,
)

@Serializable
data class PkgInventoryPayload(
    val os:          String = "android",
    val osVersion:   String,
    val deviceModel: String,
    val packages:    List<PackageEntry>,
    val totalCount:  Int,
)

@Serializable
data class ProcessEntry(
    val pid:           Int,
    val processName:   String,
    val importance:    Int,
    val importanceStr: String,  // FOREGROUND, BACKGROUND, SERVICE, …
    val uid:           Int,
)

@Serializable
data class ProcessListPayload(
    val processes: List<ProcessEntry>,
)
