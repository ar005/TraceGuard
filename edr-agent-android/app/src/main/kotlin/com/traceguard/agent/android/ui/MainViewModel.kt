package com.traceguard.agent.android.ui

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.traceguard.agent.android.config.ConfigRepository
import com.traceguard.agent.buffer.EventBuffer
import com.traceguard.agent.config.AgentConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

data class AgentUiState(
    val agentId:      String  = "",
    val backendHost:  String  = "192.168.1.100",
    val backendPort:  Int     = 50051,
    val useTls:       Boolean = false,
    val apiToken:     String  = "",
    val bufferCount:  Long    = 0,
    val serviceRunning: Boolean = false,
)

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cfgRepo: ConfigRepository,
    private val buffer:  EventBuffer,
) : ViewModel() {

    private val _state = MutableStateFlow(AgentUiState())
    val state: StateFlow<AgentUiState> = _state.asStateFlow()

    init {
        loadConfig()
        startPolling()
    }

    private fun loadConfig() {
        val cfg = cfgRepo.load()
        _state.value = _state.value.copy(
            agentId     = cfg.agentId,
            backendHost = cfg.backendHost,
            backendPort = cfg.backendPort,
            useTls      = cfg.useTls,
            apiToken    = cfg.apiToken,
        )
    }

    private fun startPolling() {
        viewModelScope.launch {
            while (isActive) {
                _state.value = _state.value.copy(bufferCount = buffer.count())
                delay(2_000)
            }
        }
    }

    fun onHostChanged(host: String)        { _state.value = _state.value.copy(backendHost = host) }
    fun onPortChanged(port: String)        { _state.value = _state.value.copy(backendPort = port.toIntOrNull() ?: 50051) }
    fun onTlsChanged(tls: Boolean)         { _state.value = _state.value.copy(useTls = tls) }
    fun onTokenChanged(token: String)      { _state.value = _state.value.copy(apiToken = token) }

    fun saveAndApply() {
        val s = _state.value
        cfgRepo.save(AgentConfig(
            backendHost = s.backendHost,
            backendPort = s.backendPort,
            useTls      = s.useTls,
            apiToken    = s.apiToken,
            agentId     = s.agentId,
        ))
    }
}
