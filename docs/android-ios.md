# Android & iOS — EDR Agent + Analyst UI

TraceGuard mobile expansion: Android/iOS endpoint sensor and a cross-platform analyst dashboard.

---

## Tech Stack Decision

### Why not Flutter for the agent?

Flutter is a UI framework. It cannot directly call Android system APIs (`PackageManager`, `AppOpsManager`, `ConnectivityManager`, `AccessibilityService`) or iOS equivalents without native platform channels for every call — which is more complex than just writing native Kotlin/Swift. The agent is a system-level foreground service, not a UI app.

### Why Flutter for the analyst UI?

The analyst UI is a pure API consumer (REST + SSE + JWT). Flutter produces a single Dart codebase that runs on Android, iOS, and the web (PWA) from one project. Material 3 on Android and Cupertino adaptations on iOS come automatically.

### Why Kotlin Multiplatform (KMP) for the agent core?

The agent's platform-independent logic — gRPC transport, SQLite event buffer, retry policy, heartbeat, config, event struct definitions — can be written once in Kotlin and compiled for both Android (JVM) and iOS (Kotlin/Native). Each platform then adds a thin native layer for OS API calls.

### Why not Java?

Java is the legacy Android language. Kotlin is the official replacement since 2019, is strictly more expressive, has built-in coroutines/Flow, and is fully interoperable with existing Java Android libraries.

---

## Component Map

```
edr-agent-kmp/        ← Kotlin Multiplatform: shared transport, buffer, events, config
edr-agent-android/    ← Kotlin (Android system APIs + foreground service)
edr-agent-ios/        ← Swift (iOS system APIs + MDM integration)
edr-flutter/          ← Flutter/Dart: analyst UI for Android + iOS + Web
```

No proto changes required. `EventEnvelope.os` already accepts any string; Android agents set `os = "android"`, iOS agents set `os = "ios"`.

---

## Part 1 — `edr-agent-kmp/` (Kotlin Multiplatform Shared Core)

Shared business logic compiled for Android (JVM) and iOS (Kotlin/Native via XCFramework).

### Module structure

```
edr-agent-kmp/
├── shared/
│   ├── src/
│   │   ├── commonMain/kotlin/com/traceguard/agent/
│   │   │   ├── events/
│   │   │   │   ├── EventEnvelope.kt        ← mirrors proto fields as data class
│   │   │   │   ├── EventTypes.kt           ← all event type constants
│   │   │   │   └── Payload.kt              ← typed payload structs (kotlinx.serialization)
│   │   │   ├── transport/
│   │   │   │   ├── GrpcTransport.kt        ← grpc-kotlin, event streaming + heartbeat
│   │   │   │   └── RetryPolicy.kt          ← exponential backoff with jitter
│   │   │   ├── buffer/
│   │   │   │   └── EventBuffer.kt          ← SQLDelight schema (compiles to SQLite on both platforms)
│   │   │   ├── config/
│   │   │   │   └── AgentConfig.kt          ← backend URL, agent ID, intervals, token
│   │   │   ├── heartbeat/
│   │   │   │   └── Heartbeat.kt            ← periodic heartbeat + config_version check
│   │   │   └── registration/
│   │   │       └── Registration.kt         ← Register RPC, assigned_id storage
│   │   ├── androidMain/kotlin/             ← Android-specific expect/actual (e.g. UUID)
│   │   └── iosMain/kotlin/                 ← iOS-specific expect/actual
│   └── build.gradle.kts
├── gradle/
└── build.gradle.kts
```

### Key libraries (KMP)

| Library | Purpose |
|---------|---------|
| `io.grpc:grpc-kotlin-stub` | gRPC client stubs |
| `com.squareup.sqldelight` | SQLite buffer (KMP-compatible) |
| `org.jetbrains.kotlinx:kotlinx-serialization-json` | JSON payload serialization |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` | async / Flow |
| `io.ktor:ktor-client-core` | HTTP fallback (REST registration) |

---

## Part 2 — `edr-agent-android/` (Android Sensor)

Thin Kotlin layer over the KMP core. Runs as a persistent **foreground service** (required on Android 8+).

### Module structure

```
edr-agent-android/
├── app/
│   ├── src/main/
│   │   ├── java/com/traceguard/agent/android/
│   │   │   ├── AgentApplication.kt         ← Hilt application class
│   │   │   ├── service/
│   │   │   │   └── TraceGuardService.kt    ← foreground service, starts all monitors
│   │   │   ├── monitor/
│   │   │   │   ├── Monitor.kt              ← common interface: start(scope), stop()
│   │   │   │   ├── AppInstallMonitor.kt    ← ACTION_PACKAGE_ADDED / REMOVED / REPLACED
│   │   │   │   ├── NetworkMonitor.kt       ← ConnectivityManager.NetworkCallback
│   │   │   │   ├── PermissionMonitor.kt    ← AppOpsManager.OnOpChangedListener
│   │   │   │   ├── DeviceAdminMonitor.kt   ← DevicePolicyManager state + broadcasts
│   │   │   │   ├── ScreenMonitor.kt        ← ACTION_SCREEN_ON/OFF, ACTION_USER_PRESENT
│   │   │   │   ├── UsbMonitor.kt           ← ACTION_USB_DEVICE_ATTACHED/DETACHED
│   │   │   │   ├── WifiMonitor.kt          ← WifiManager.NETWORK_STATE_CHANGED_ACTION
│   │   │   │   ├── AccessibilityMonitor.kt ← polls enabled accessibility services list
│   │   │   │   ├── BatteryMonitor.kt       ← ACTION_BATTERY_LOW, ACTION_POWER_CONNECTED
│   │   │   │   ├── VulnMonitor.kt          ← getInstalledPackages() every 6h → PKG_INVENTORY
│   │   │   │   └── ProcessMonitor.kt       ← ActivityManager.getRunningAppProcesses()
│   │   │   ├── containment/
│   │   │   │   └── Containment.kt          ← VpnService (no root) or airplane mode
│   │   │   ├── liveresponse/
│   │   │   │   └── LiveResponseHandler.kt  ← pm, dumpsys, ps, ls, cat, getprop, kill
│   │   │   └── receiver/
│   │   │       └── BootReceiver.kt         ← restart service on device reboot
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
└── build.gradle.kts
```

### Monitors and event types

| Monitor | Android API Used | Event Types Emitted |
|---------|-----------------|---------------------|
| `AppInstallMonitor` | `PackageManager` broadcasts | `APP_INSTALL`, `APP_REMOVE`, `APP_UPDATE` |
| `NetworkMonitor` | `ConnectivityManager.NetworkCallback` | `NET_CONNECT`, `NET_DISCONNECT` |
| `PermissionMonitor` | `AppOpsManager.OnOpChangedListener` | `PERM_GRANT`, `PERM_REVOKE` |
| `DeviceAdminMonitor` | `DevicePolicyManager` + broadcasts | `DEVICE_ADMIN_CHANGE` |
| `ScreenMonitor` | `ACTION_SCREEN_ON/OFF` | `SCREEN_EVENT` |
| `UsbMonitor` | `ACTION_USB_DEVICE_ATTACHED/DETACHED` | `USB_DEVICE` |
| `WifiMonitor` | `WifiManager.NETWORK_STATE_CHANGED_ACTION` | `WIFI_CONNECT`, `WIFI_DISCONNECT` |
| `AccessibilityMonitor` | `AccessibilityManager.getEnabledAccessibilityServiceList()` | `ACCESSIBILITY_SERVICE` |
| `BatteryMonitor` | Battery intents | `POWER_EVENT` |
| `VulnMonitor` | `PackageManager.getInstalledPackages()` | `PKG_INVENTORY` |
| `ProcessMonitor` | `ActivityManager.getRunningAppProcesses()` | `PROCESS_LIST` |

No root required. Device Owner/admin features are opt-in and unlock deeper AppOps access and network containment.

### Permissions required (AndroidManifest.xml)

```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
<uses-permission android:name="android.permission.PACKAGE_USAGE_STATS" />     <!-- AppOps -->
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />      <!-- package inventory -->
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.USB_PERMISSION" />
```

### Live response commands (Android subset)

| Command | Implementation |
|---------|---------------|
| `pm list packages` | `PackageManager.getInstalledPackages()` |
| `ps` | `ActivityManager.getRunningAppProcesses()` |
| `dumpsys battery` | Shell via `Runtime.exec("dumpsys battery")` |
| `getprop` | `android.os.SystemProperties` |
| `ls <path>` | `File.listFiles()` |
| `cat <path>` | `FileInputStream` (app-accessible paths only) |
| `id` | `android.os.Process.myUid()` |
| `netstat` | Parse `/proc/net/tcp` + `/proc/net/tcp6` |
| `kill <pid>` | `android.os.Process.killProcess(pid)` |
| `isolate` | Enable `VpnService` blocking all traffic except backend |
| `release` | Disconnect VPN |

Dangerous patterns (`rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`) are blocked at the `LiveResponseHandler` level, matching the Linux/Windows agent behavior.

### Build

```bash
cd edr-agent-android
./gradlew assembleDebug            # debug APK
./gradlew assembleRelease          # signed release APK
./gradlew connectedAndroidTest     # instrumented tests on device/emulator
```

Requirements: Android Studio Hedgehog+ or JDK 17 + Android SDK 35.

---

## Part 3 — `edr-agent-ios/` (iOS Sensor)

iOS is significantly more sandboxed than Android. Most EDR capabilities require **MDM enrollment** (Supervised mode) or a **Network Extension** entitlement. This component targets enterprise-managed iPhones.

### What iOS allows without MDM

| Capability | Available? |
|-----------|-----------|
| App install monitoring | No (sandboxed) |
| Process list | No |
| Network connections | Via `Network.framework` (own process only) |
| Device info | Yes (`UIDevice`, `ProcessInfo`) |
| Battery/power events | Yes (`UIDevice.batteryStateDidChangeNotification`) |
| Background execution | Limited (BackgroundTasks framework, 30s max) |

### What MDM/Supervised mode unlocks

| Capability | API |
|-----------|-----|
| App inventory | `MDMClient` / DEP enrollment |
| Network traffic | `NEPacketTunnelProvider` (Network Extension) |
| Per-app VPN (containment) | `NEAppProxyProvider` |
| Certificate management | `CertificateManagement` |
| Device restrictions | `DeviceManagement` framework |

### Module structure

```
edr-agent-ios/
├── TraceGuardAgent/
│   ├── AgentApp.swift                  ← @main entry point
│   ├── Service/
│   │   ├── BackgroundTaskScheduler.swift ← BGTaskScheduler (iOS background)
│   │   └── AgentService.swift           ← coordinates KMP core + iOS monitors
│   ├── Monitor/
│   │   ├── DeviceMonitor.swift          ← battery, thermal, connectivity
│   │   ├── NetworkMonitor.swift         ← NWPathMonitor for connectivity changes
│   │   ├── AppInventoryMonitor.swift    ← MDM-only: app list via ManagedAppList
│   │   └── LocationMonitor.swift        ← optional, with permission
│   ├── Transport/
│   │   └── GrpcBridge.swift             ← calls into KMP GrpcTransport via Swift/Kotlin interop
│   └── NetworkExtension/
│       └── PacketTunnelProvider.swift   ← containment: blocks all traffic except backend
├── TraceGuardAgent.xcodeproj
└── Podfile / Package.swift
```

### iOS limitations and mitigations

| Limitation | Mitigation |
|-----------|-----------|
| No persistent background process | `BGProcessingTask` for periodic sync; `NEPacketTunnelProvider` keeps network extension alive |
| No app install monitoring | MDM enrollment provides managed app list; poll for changes every heartbeat |
| No process list | Report running foreground app via `UIApplication` callbacks |
| ATS (App Transport Security) | Backend must present a valid TLS certificate; self-signed requires ATS exception in Info.plist |

---

## Part 4 — `edr-flutter/` (Cross-Platform Analyst UI)

One Flutter/Dart codebase → Android APK + iOS IPA + Web PWA.

### Module structure

```
edr-flutter/
├── lib/
│   ├── main.dart
│   ├── app.dart                          ← MaterialApp, router, theme
│   ├── auth/
│   │   ├── login_screen.dart
│   │   └── auth_provider.dart            ← JWT storage via flutter_secure_storage
│   ├── navigation/
│   │   └── app_router.dart               ← go_router: bottom nav + nested routes
│   ├── dashboard/
│   │   ├── dashboard_screen.dart         ← summary cards, sparklines
│   │   └── dashboard_provider.dart
│   ├── agents/
│   │   ├── agents_screen.dart            ← agent list, online/offline status
│   │   ├── agent_detail_screen.dart      ← 4 tabs: overview, events, alerts, packages
│   │   └── agents_provider.dart
│   ├── alerts/
│   │   ├── alerts_screen.dart            ← filterable list, severity chips
│   │   ├── alert_detail_screen.dart
│   │   └── alerts_provider.dart
│   ├── incidents/
│   │   ├── incidents_screen.dart
│   │   ├── incident_detail_screen.dart   ← correlated alerts, MITRE tags, timeline
│   │   └── incidents_provider.dart
│   ├── events/
│   │   ├── events_screen.dart            ← SSE live stream, pause/resume
│   │   └── events_provider.dart
│   ├── hunt/
│   │   ├── hunt_screen.dart              ← multi-line query input + results table
│   │   └── hunt_provider.dart
│   ├── live_response/
│   │   ├── live_response_screen.dart     ← terminal-style UI (monospace, scrolling output)
│   │   └── live_response_provider.dart
│   ├── network/
│   │   ├── api_client.dart               ← Dio HTTP client, JWT interceptor
│   │   ├── sse_client.dart               ← Server-Sent Events via fetch (web) / Dio (mobile)
│   │   └── edr_api.dart                  ← all REST endpoint methods
│   └── settings/
│       └── settings_screen.dart          ← backend URL, API key, theme selector
├── test/
├── pubspec.yaml
└── README.md
```

### Screen mapping (edr-ui-new → edr-flutter)

| edr-ui-new | edr-flutter screen | Notes |
|------------|-------------------|-------|
| `/` dashboard | `DashboardScreen` | Summary cards + mini charts (fl_chart) |
| `/agents` + `/agents/[id]` | `AgentsScreen` + `AgentDetailScreen` | Pull-to-refresh, OS badge (linux/windows/android/ios) |
| `/alerts` | `AlertsScreen` + `AlertDetailScreen` | Swipe actions for status change |
| `/incidents` | `IncidentsScreen` + `IncidentDetailScreen` | Timeline via ListView |
| `/events` | `EventsScreen` | SSE live stream with type/agent filter chips |
| `/hunt` | `HuntScreen` | Query templates bottom sheet |
| `/live-response` | `LiveResponseScreen` | Monospace terminal, command history |
| `/settings` | `SettingsScreen` | Backend URL, API key, 7 themes |

### Flutter dependencies

```yaml
dependencies:
  flutter:
    sdk: flutter
  go_router: ^14.0.0               # navigation
  riverpod: ^2.5.0                 # state management
  dio: ^5.4.0                      # HTTP client
  flutter_secure_storage: ^9.0.0   # JWT (KeyStore/Keychain backed)
  fl_chart: ^0.68.0                # sparklines + bar charts
  shared_preferences: ^2.2.0       # settings persistence
  intl: ^0.19.0                    # date formatting
  google_fonts: ^6.2.0             # typography (Geist Mono for terminal)

dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.0
  build_runner: ^2.4.0
```

### Build and run

```bash
cd edr-flutter

# Android
flutter run -d android
flutter build apk --release

# iOS
flutter run -d ios
flutter build ios --release

# Web (PWA)
flutter build web --release
# Deploy build/web/ to any static host or alongside edr-ui-new

# Tests
flutter test
flutter analyze
```

Set backend URL in `SettingsScreen` or via `--dart-define=BACKEND_URL=http://localhost:8080`.

---

## Part 5 — Backend additions (minimal)

### New Android/iOS event types recognized by detection engine

Add to detection rule seed data in a new migration:

```sql
-- Migration: add Android detection rules
INSERT INTO rules (id, name, description, event_types, conditions, severity, enabled, rule_type, mitre_tactics, mitre_techniques)
VALUES
  ('android-001', 'Android: Malicious App Install',
   'App installed with dangerous permission combination (accessibility + SMS + contacts)',
   ARRAY['APP_INSTALL'],
   '{"permissions_contains": ["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_SMS", "READ_CONTACTS"]}',
   'HIGH', true, 'match', ARRAY['Defense Evasion'], ARRAY['T1624']),

  ('android-002', 'Android: Accessibility Service Abuse',
   'Accessibility service enabled for unknown or suspicious package',
   ARRAY['ACCESSIBILITY_SERVICE'],
   '{"unknown_package": true}',
   'HIGH', true, 'match', ARRAY['Collection'], ARRAY['T1624.001']),

  ('android-003', 'Android: Device Admin Escalation',
   'Unknown app gained device administrator privileges',
   ARRAY['DEVICE_ADMIN_CHANGE'],
   '{"action": "enabled", "known_admin": false}',
   'CRITICAL', true, 'match', ARRAY['Privilege Escalation'], ARRAY['T1626']),

  ('android-004', 'Android: USB Debugging Enabled',
   'USB debugging was enabled on the device',
   ARRAY['USB_DEVICE'],
   '{"debug_enabled": true}',
   'MEDIUM', true, 'match', ARRAY['Initial Access'], ARRAY['T1200']),

  ('android-005', 'Android: Suspicious Permission Grant',
   'Dangerous runtime permission granted to background-only app',
   ARRAY['PERM_GRANT'],
   '{"permission_in": ["READ_SMS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION"], "background_only": true}',
   'HIGH', true, 'match', ARRAY['Collection'], ARRAY['T1430']),

  ('android-006', 'Android: Cryptominer Behavior',
   'Sustained high CPU from background app with outbound mining pool connections',
   ARRAY['POWER_EVENT'],
   '{"high_cpu": true, "mining_pool_connection": true}',
   'HIGH', true, 'match', ARRAY['Impact'], ARRAY['T1496']);
```

### New hunt query templates

Add to the hunt query template seed (or UI template list):

```sql
-- Android app installs in last 24h
event_type = 'APP_INSTALL' AND timestamp > NOW() - INTERVAL '24 hours'

-- Apps granted dangerous permissions
event_type = 'PERM_GRANT' AND payload->>'permission' IN ('READ_SMS','RECORD_AUDIO','CAMERA')

-- Device admin changes
event_type = 'DEVICE_ADMIN_CHANGE' AND payload->>'action' = 'enabled'

-- Android agents overview
event_type = 'PKG_INVENTORY' AND payload->>'os' = 'android'
```

### edr-ui-new additions

- Agent list: show OS badge for `android` / `ios` (orange/blue pill, similar to existing `linux`/`windows`)
- Agent detail: `App Inventory` tab (replaces `Packages` tab for Android/iOS agents) sourced from `PKG_INVENTORY` events
- No other UI changes required — all existing pages (alerts, incidents, events, hunt) work automatically because they filter by `event_type`, not `os`

---

## Part 6 — Phased delivery

### Phase 1 — Android agent MVP (2–3 weeks)
1. `edr-agent-kmp/` scaffold: gRPC transport + SQLDelight buffer + heartbeat + registration
2. `edr-agent-android/`: foreground service, `AppInstallMonitor`, `NetworkMonitor`, `VulnMonitor`
3. Basic `LiveResponseHandler` (pm, ps, dumpsys)
4. Agent registers in backend, events appear in edr-ui-new with `os: android` badge

### Phase 2 — Full Android agent (1–2 weeks)
5. Remaining 8 monitors (permission, device admin, screen, USB, WiFi, accessibility, battery, process)
6. Containment via `VpnService` (no root)
7. `BootReceiver` for persistence after reboot
8. Config hot-reload via `config_version` in heartbeat response

### Phase 3 — Flutter analyst UI MVP (2 weeks)
9. `edr-flutter/` scaffold: router, auth, settings, API client
10. `DashboardScreen`, `AgentsScreen`, `AlertsScreen` with live data
11. `IncidentDetailScreen` with correlated alert timeline

### Phase 4 — Full Flutter UI (1 week)
12. `EventsScreen` with SSE live stream
13. `HuntScreen` with query templates
14. `LiveResponseScreen` terminal
15. 7 color themes matching edr-ui-new theme set
16. Web build (`flutter build web`) — deploy alongside edr-ui-new

### Phase 5 — iOS agent (2–3 weeks, post-Android)
17. `edr-agent-ios/` Swift skeleton consuming KMP core via XCFramework
18. `DeviceMonitor` + `NetworkMonitor` (NWPathMonitor)
19. `NEPacketTunnelProvider` for containment
20. MDM enrollment guide for full app inventory access

### Phase 6 — Backend rules + UI polish (1 week)
21. 6 Android detection rules via DB migration
22. Android/iOS hunt query templates
23. OS badge in edr-ui-new agent list and detail pages

---

## Key decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Agent language (Android) | **Kotlin** | Only option for Android system APIs |
| Agent language (iOS) | **Swift** | Only option for iOS system APIs |
| Shared agent logic | **Kotlin Multiplatform** | Write transport/buffer/config once, compile to Android JVM + iOS Kotlin/Native |
| Analyst UI | **Flutter** | Single Dart codebase → Android + iOS + Web from one project |
| Analyst UI state management | **Riverpod** | Compile-safe, testable, no boilerplate vs BLoC |
| Android gRPC transport | **grpc-kotlin-stub + OkHttp** | Android-compatible gRPC stack |
| Android SQLite buffer | **SQLDelight** | KMP-compatible, type-safe SQL |
| iOS background execution | **BGProcessingTask + NEPacketTunnelProvider** | Only reliable iOS background mechanisms |
| Containment (Android, no root) | **VpnService** | Blocks all traffic except backend without root |
| Containment (Android, Device Owner) | **setAlwaysOnVpnPackage** | MDM-managed, persistent |
| Min Android SDK | **26 (Android 8.0)** | Foreground service notification requirement |
| Min iOS | **16.0** | `DeviceManagement` framework, modern Swift concurrency |

---

## References

- Linux agent: `edr-agent/` — eBPF-based, reference for monitor interface and buffer pattern
- Windows agent: `edr-agent-win/` — closest analog (no kernel access, polling monitors)
- Proto contract: `edr-backend/proto/edr.proto` — single source of truth for agent↔backend wire format
- Backend detection: `edr-backend/internal/detection/engine.go`
- Primary analyst UI: `edr-ui-new/` — Next.js 16 reference for feature parity
