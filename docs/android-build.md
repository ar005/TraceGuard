# Building the Android EDR Agent in Android Studio

Step-by-step guide to compile `edr-agent-android/` into a working APK.

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Android Studio | Hedgehog (2023.1.1) or newer | https://developer.android.com/studio |
| JDK | 17 (bundled with Android Studio) | included |
| Android SDK | API 35 (auto-installed) | via SDK Manager |
| Android Build Tools | 34.0.0+ | via SDK Manager |
| NDK | not required | — |

> Android Studio already bundles a JDK 17. You do **not** need to install Java separately.

---

## Step 1 — Open the project

1. Launch Android Studio.
2. On the Welcome screen click **Open** (or **File → Open** if a project is already open).
3. Navigate to:
   ```
   /home/devubuntu/projects/TraceGuard/edr-agent-android
   ```
4. Click **OK**. Android Studio detects the `settings.gradle.kts` and loads the project.

> **Do not** open the repo root (`TraceGuard/`) — open `edr-agent-android/` specifically.

---

## Step 2 — Let Gradle sync finish

After opening, Android Studio runs an initial Gradle sync to download all dependencies (~400 MB on first run — needs internet). Watch the progress bar at the bottom.

If sync fails, the most common fixes are:

| Error | Fix |
|-------|-----|
| `SDK location not found` | Open **File → Project Structure → SDK Location** and set the Android SDK path (usually `~/Android/Sdk`) |
| `Unsupported class file major version` | **File → Project Structure → SDK** → set Gradle JDK to **JDK 17** (the one bundled with Android Studio: `jbr-17`) |
| `Could not resolve io.grpc:grpc-kotlin-stub` | Check internet connection; behind a proxy add proxy settings to `~/.gradle/gradle.properties` |
| `Plugin [id: 'com.google.protobuf'] was not found` | Same — Gradle plugin portal must be reachable |

To manually re-trigger sync: **File → Sync Project with Gradle Files** (or click the elephant+refresh icon in the toolbar).

---

## Step 3 — Install the missing SDK (if prompted)

If Android Studio shows a yellow banner saying **"Install missing SDK components"**, click **Install** and accept the license. This installs:
- Android SDK Platform 35
- Android Build Tools 34.0.0

Wait for it to finish, then sync again.

---

## Step 4 — Configure a device or emulator

### Option A — Physical Android device (recommended for EDR testing)

1. On the Android device, enable **Developer Options**:
   - Go to **Settings → About Phone**
   - Tap **Build Number** 7 times
2. In **Developer Options**, enable:
   - **USB Debugging**
   - **Install via USB**
3. Connect the device via USB cable.
4. Accept the "Allow USB debugging?" dialog on the device.
5. In Android Studio, the device appears in the target device dropdown (top toolbar).

> The EDR agent monitors app installs, network changes, and package inventory — these all work on a physical device. Some features (AppOps permission monitoring) require a real device.

### Option B — Android Emulator

1. Open **Device Manager** (toolbar icon or **View → Tool Windows → Device Manager**).
2. Click **Create Device**.
3. Choose **Pixel 7** (or any phone profile), click **Next**.
4. Select system image: **API 35 (Android 15), x86_64**, download if needed, click **Next → Finish**.
5. Click the ▶ button to start the emulator.

> The emulator works for basic testing (UI, gRPC transport, Room buffer) but `AppInstallMonitor` broadcast receivers behave differently than on a real device.

---

## Step 5 — Configure backend connection before first run

The agent needs to know where your `edr-backend` is running. Set this **before** building:

Open `app/src/main/kotlin/com/traceguard/agent/android/config/ConfigRepository.kt` and note the defaults:

```kotlin
backendHost = prefs.getString(KEY_HOST, "192.168.1.100")!!,
backendPort = prefs.getInt(KEY_PORT, 50051),
```

You can change these defaults here, **or** configure them at runtime via the app's Settings screen after install.

### Finding your backend IP

```bash
# On the machine running edr-backend:
ip addr show | grep "inet " | grep -v 127.0.0.1
# e.g. 192.168.1.55
```

If backend is running on the same machine as the emulator, use `10.0.2.2` (the emulator's alias for the host machine's localhost).

### Make sure backend is running

```bash
cd /home/devubuntu/projects/TraceGuard/edr-backend
make run
# gRPC should be listening on :50051
```

---

## Step 6 — Build the debug APK

### Via Android Studio UI

1. In the toolbar, select the **app** module in the left dropdown (next to the run button).
2. Select your device/emulator in the right dropdown.
3. Click **▶ Run** (Shift+F10).

Android Studio will:
1. Compile the `shared` KMP module → `shared-debug.aar`
2. Run `protoc` to generate gRPC Java + Kotlin stubs from `edr.proto`
3. Run KSP to generate Room DAO implementations and Hilt factories
4. Compile the `app` module
5. Package the APK
6. Install and launch it on the selected device

### Via terminal (Gradle wrapper)

```bash
cd /home/devubuntu/projects/TraceGuard/edr-agent-android

# Debug APK (fastest, no signing required)
./gradlew :app:assembleDebug

# Output: app/build/outputs/apk/debug/app-debug.apk

# Install directly to connected device
./gradlew :app:installDebug

# Run all unit tests
./gradlew :shared:testDebugUnitTest
./gradlew :app:testDebugUnitTest
```

---

## Step 7 — Grant required permissions after install

Several permissions require manual approval on first launch:

| Permission | Where to grant |
|-----------|---------------|
| **PACKAGE_USAGE_STATS** | Settings → Apps → Special app access → Usage access → TraceGuard EDR → Allow |
| **QUERY_ALL_PACKAGES** | Automatically granted (declared in manifest) |
| **Appear on top / Overlay** | Not needed for Phase 1 |

The `PACKAGE_USAGE_STATS` permission is required for `VulnMonitor` to read the full package list. Without it, only the app's own packages are visible.

To open Usage Access settings programmatically (already wired in the UI — Phase 2):
```
Settings.ACTION_USAGE_ACCESS_SETTINGS
```

---

## Step 8 — Verify the agent is working

1. Open the **TraceGuard EDR** app.
2. In the Settings card, enter your backend host IP and port.
3. Tap **Save Settings**.
4. Tap **Start Monitoring**.
5. The persistent notification should change from "Starting…" to "Monitoring active".

### Check agent registration in the backend logs

```bash
# On the backend machine:
tail -f /tmp/edr-backend.log   # or however you run it
# Look for:
# registered agent  agent_id=android-xxxx  os=android  hostname=Samsung-Galaxy
```

### Check agent appears in edr-ui-new

Open `http://localhost:5002` → **Agents** page. The Android agent should appear with an `android` OS badge.

### Check events flowing

Open the **Events** page in edr-ui-new. Install any app on the Android device — an `APP_INSTALL` event should appear within a few seconds.

---

## Step 9 — Build a release APK (for sideloading to a fleet)

Release builds are minified and need a signing keystore.

### Generate a keystore (one time)

```bash
keytool -genkeypair \
  -alias traceguard \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -keystore traceguard-release.jks \
  -storepass changeme \
  -keypass changeme \
  -dname "CN=TraceGuard, OU=Security, O=YourOrg, L=City, ST=State, C=US"
```

### Configure signing in `app/build.gradle.kts`

Add before the `buildTypes` block:

```kotlin
signingConfigs {
    create("release") {
        storeFile     = file("../../traceguard-release.jks")
        storePassword = System.getenv("KS_PASS") ?: "changeme"
        keyAlias      = "traceguard"
        keyPassword   = System.getenv("KEY_PASS") ?: "changeme"
    }
}

buildTypes {
    release {
        isMinifyEnabled   = true
        signingConfig     = signingConfigs.getByName("release")
        proguardFiles(
            getDefaultProguardFile("proguard-android-optimize.txt"),
            "proguard-rules.pro"
        )
    }
}
```

### Build

```bash
KS_PASS=changeme KEY_PASS=changeme \
  ./gradlew :app:assembleRelease

# Output: app/build/outputs/apk/release/app-release.apk
```

### Install on a device without Android Studio

```bash
# Via ADB (USB or TCP/IP)
adb install -r app/build/outputs/apk/release/app-release.apk

# Or copy the APK and sideload via Files app on device
# (requires "Install from unknown sources" enabled)
```

---

## Troubleshooting common build errors

### `error: cannot find symbol — EventServiceGrpcKt`

The gRPC Kotlin stubs were not generated. Fix:

```bash
./gradlew :app:generateDebugProto
```

Then re-sync. The generated files appear in:
```
app/build/generated/source/proto/debug/
├── grpc/          ← Java service stubs
├── grpckt/        ← Kotlin coroutine stubs  ← this is what we use
└── kotlin/        ← Kotlin data class extensions
```

If they are missing, check that `protoc` can be downloaded. It fetches a platform-specific binary from Maven Central.

---

### `KSP: [ksp] error: ... Room cannot verify the data integrity`

Room schema export is disabled (`exportSchema = false` in `EventDatabase`). This warning can be ignored in debug builds.

---

### `Hilt: ... is not annotated with @AndroidEntryPoint`

Occurs if you subclass an activity or service that needs injection without the annotation. All injectable entry points are already annotated in the current codebase.

---

### `grpc-okhttp: UNAVAILABLE: io exception`

The backend is not reachable from the device:
1. Confirm backend is running: `curl http://<backend-ip>:8080/api/v1/health`
2. Confirm port 50051 is not firewalled: `nc -zv <backend-ip> 50051`
3. On emulator, use `10.0.2.2` instead of `localhost` or `127.0.0.1`
4. If using TLS, ensure the certificate is trusted (add to network security config or use user cert)

---

### `cleartext HTTP traffic not permitted`

The `network_security_config.xml` already permits cleartext for development. If this error still appears, ensure the `android:networkSecurityConfig` attribute is set on `<application>` in `AndroidManifest.xml`.

---

## Project structure quick reference

```
edr-agent-android/
├── shared/              ← Kotlin Multiplatform library (future iOS reuse)
│   └── src/commonMain/  ← platform-independent Kotlin
│       ├── agent/       AgentCore, Registration, HeartbeatTracker
│       ├── events/      EventTypes, EventEnvelope, Payloads, LiveResponse
│       ├── buffer/      EventBuffer interface
│       ├── transport/   Transport interface
│       ├── monitor/     Monitor interface
│       └── config/      AgentConfig
│
└── app/                 ← Android application
    └── src/main/
        ├── proto/       edr.proto → protoc generates gRPC stubs here
        ├── kotlin/
        │   └── com/traceguard/agent/android/
        │       ├── AgentApplication.kt   Hilt @HiltAndroidApp
        │       ├── buffer/               Room database + DAO
        │       ├── config/               ConfigRepository (SharedPreferences)
        │       ├── di/                   Hilt module (wires everything together)
        │       ├── liveresponse/         LiveResponseHandler (ps, ls, cat, pm…)
        │       ├── monitor/              AppInstallMonitor, NetworkMonitor, VulnMonitor
        │       ├── service/              TraceGuardService (foreground), BootReceiver
        │       ├── transport/            GrpcTransport (grpc-kotlin coroutines)
        │       └── ui/                   MainActivity (Compose), MainViewModel
        ├── res/xml/     network_security_config.xml
        └── AndroidManifest.xml
```

---

## What each module builds to

| Gradle task | Output |
|------------|--------|
| `:shared:assembleDebug` | `shared/build/outputs/aar/shared-debug.aar` (KMP library) |
| `:app:assembleDebug` | `app/build/outputs/apk/debug/app-debug.apk` |
| `:app:assembleRelease` | `app/build/outputs/apk/release/app-release.apk` |
| `:app:generateDebugProto` | gRPC stubs under `app/build/generated/source/proto/` |
| `:app:kspDebugKotlin` | Room + Hilt generated code |

---

## Next steps after a successful build

- **Phase 2 monitors**: Add `PermissionMonitor`, `DeviceAdminMonitor`, `ScreenMonitor`, `UsbMonitor`, `WifiMonitor`, `AccessibilityMonitor`, `BatteryMonitor`, `ProcessMonitor` — each follows the same pattern as the three Phase 1 monitors.
- **Flutter analyst UI**: `edr-flutter/` (Phase 3) — separate Flutter project, connects to the same REST backend on `:8080`.
- **iOS agent**: Add `iosArm64()` target to `shared/build.gradle.kts` and create `edr-agent-ios/` Swift project consuming the KMP XCFramework.
