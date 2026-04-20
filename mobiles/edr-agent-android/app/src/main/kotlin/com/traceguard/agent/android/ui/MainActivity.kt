package com.traceguard.agent.android.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.traceguard.agent.android.service.ContainmentState
import com.traceguard.agent.android.service.TraceGuardService
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        vm.onVpnPermissionResult(result.resultCode == Activity.RESULT_OK)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val state by vm.state.collectAsState()

                    // If containment tried to isolate but VPN permission is missing, prompt
                    LaunchedEffect(state.needsVpnPermission) {
                        if (state.needsVpnPermission) {
                            VpnService.prepare(this@MainActivity)?.let { intent ->
                                vpnPermissionLauncher.launch(intent)
                            } ?: vm.onVpnPermissionResult(true) // already granted
                        }
                    }

                    AgentScreen(
                        state   = state,
                        onStart = { TraceGuardService.start(this) },
                        onStop  = { TraceGuardService.stop(this) },
                        onRequestVpnPermission = {
                            VpnService.prepare(this)?.let { intent ->
                                vpnPermissionLauncher.launch(intent)
                            }
                        },
                        vm = vm,
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentScreen(
    state:                AgentUiState,
    onStart:              () -> Unit,
    onStop:               () -> Unit,
    onRequestVpnPermission: () -> Unit,
    vm:                   MainViewModel,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("TraceGuard EDR", style = MaterialTheme.typography.headlineMedium)

        // ── Containment banner ──────────────────────────────────────────────
        when (state.containmentState) {
            ContainmentState.ISOLATED -> ContainmentBanner(
                label = "DEVICE ISOLATED",
                description = "All network traffic is blocked. Backend comms remain active.",
                color = MaterialTheme.colorScheme.error,
            )
            ContainmentState.PERMISSION_REQUIRED -> ContainmentBanner(
                label = "VPN PERMISSION REQUIRED",
                description = "Tap below to authorise containment before the next isolate command.",
                color = Color(0xFFF59E0B),
                actionLabel = "Grant VPN Permission",
                onAction = onRequestVpnPermission,
            )
            ContainmentState.RELEASED -> Unit
        }

        // ── Status card ─────────────────────────────────────────────────────
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Agent ID", style = MaterialTheme.typography.labelSmall)
                Text(
                    state.agentId.ifBlank { "not registered" },
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(4.dp))
                Text("Buffered events: ${state.bufferCount}", style = MaterialTheme.typography.bodyMedium)
            }
        }

        // ── Settings ────────────────────────────────────────────────────────
        Text("Backend", style = MaterialTheme.typography.titleMedium)

        OutlinedTextField(
            value         = state.backendHost,
            onValueChange = vm::onHostChanged,
            label         = { Text("Host") },
            modifier      = Modifier.fillMaxWidth(),
            singleLine    = true,
        )

        OutlinedTextField(
            value         = state.backendPort.toString(),
            onValueChange = vm::onPortChanged,
            label         = { Text("gRPC Port") },
            modifier      = Modifier.fillMaxWidth(),
            singleLine    = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )

        OutlinedTextField(
            value                = state.apiToken,
            onValueChange        = vm::onTokenChanged,
            label                = { Text("API Token (optional)") },
            modifier             = Modifier.fillMaxWidth(),
            singleLine           = true,
            visualTransformation = PasswordVisualTransformation(),
        )

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = state.useTls, onCheckedChange = vm::onTlsChanged)
            Spacer(Modifier.width(8.dp))
            Text("Use TLS")
        }

        Button(onClick = { vm.saveAndApply() }, modifier = Modifier.fillMaxWidth()) {
            Text("Save Settings")
        }

        HorizontalDivider()

        // ── Service controls ────────────────────────────────────────────────
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick  = onStart,
                modifier = Modifier.weight(1f),
            ) { Text("Start Monitoring") }

            OutlinedButton(
                onClick  = onStop,
                modifier = Modifier.weight(1f),
            ) { Text("Stop") }
        }

        // VPN pre-auth hint (shown when not yet granted and not in error state)
        if (state.containmentState == ContainmentState.RELEASED) {
            OutlinedButton(
                onClick  = onRequestVpnPermission,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pre-authorise VPN Containment") }
        }
    }
}

@Composable
private fun ContainmentBanner(
    label:       String,
    description: String,
    color:       Color,
    actionLabel: String? = null,
    onAction:    (() -> Unit)? = null,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors   = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.15f)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = color)
            Text(description, style = MaterialTheme.typography.bodySmall)
            if (actionLabel != null && onAction != null) {
                Spacer(Modifier.height(4.dp))
                Button(
                    onClick = onAction,
                    colors  = ButtonDefaults.buttonColors(containerColor = color),
                ) { Text(actionLabel) }
            }
        }
    }
}
