package com.traceguard.agent.events

object EventTypes {
    // Cross-platform types (shared with Linux/Windows agents)
    const val PROCESS_EXEC   = "PROCESS_EXEC"
    const val NET_CONNECT    = "NET_CONNECT"
    const val NET_DISCONNECT = "NET_DISCONNECT"
    const val FILE_CREATE    = "FILE_CREATE"
    const val FILE_WRITE     = "FILE_WRITE"
    const val FILE_DELETE    = "FILE_DELETE"
    const val LOGIN_SUCCESS  = "LOGIN_SUCCESS"
    const val LOGIN_FAILED   = "LOGIN_FAILED"
    const val PKG_INVENTORY  = "PKG_INVENTORY"

    // Android-specific
    const val APP_INSTALL            = "APP_INSTALL"
    const val APP_REMOVE             = "APP_REMOVE"
    const val APP_UPDATE             = "APP_UPDATE"
    const val PERM_GRANT             = "PERM_GRANT"
    const val PERM_REVOKE            = "PERM_REVOKE"
    const val DEVICE_ADMIN_CHANGE    = "DEVICE_ADMIN_CHANGE"
    const val SCREEN_EVENT           = "SCREEN_EVENT"
    const val USB_DEVICE             = "USB_DEVICE"
    const val WIFI_CONNECT           = "WIFI_CONNECT"
    const val WIFI_DISCONNECT        = "WIFI_DISCONNECT"
    const val ACCESSIBILITY_SERVICE  = "ACCESSIBILITY_SERVICE"
    const val POWER_EVENT            = "POWER_EVENT"
    const val PROCESS_LIST           = "PROCESS_LIST"
}
