package com.traceguard.agent.android.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.traceguard.agent.android.service.TraceGuardService
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val state by vm.state.collectAsState()
                    AgentScreen(
                        state    = state,
                        vm       = vm,
                        onStart  = { TraceGuardService.start(this) },
                        onStop   = { TraceGuardService.stop(this) },
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentScreen(
    state:   AgentUiState,
    vm:      MainViewModel,
    onStart: () -> Unit,
    onStop:  () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("TraceGuard EDR", style = MaterialTheme.typography.headlineMedium)

        // Status card
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

        // Settings
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
            value         = state.apiToken,
            onValueChange = vm::onTokenChanged,
            label         = { Text("API Token (optional)") },
            modifier      = Modifier.fillMaxWidth(),
            singleLine    = true,
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

        Divider()

        // Service controls
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick  = onStart,
                modifier = Modifier.weight(1f),
                colors   = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            ) { Text("Start Monitoring") }

            OutlinedButton(
                onClick  = onStop,
                modifier = Modifier.weight(1f),
            ) { Text("Stop") }
        }
    }
}
