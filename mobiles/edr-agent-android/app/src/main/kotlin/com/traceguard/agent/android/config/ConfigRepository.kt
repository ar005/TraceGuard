package com.traceguard.agent.android.config

import android.content.SharedPreferences
import androidx.core.content.edit
import com.traceguard.agent.config.AgentConfig
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConfigRepository @Inject constructor(private val prefs: SharedPreferences) {

    fun load(): AgentConfig = AgentConfig(
        backendHost  = prefs.getString(KEY_HOST, "192.168.1.100")!!,
        backendPort  = prefs.getInt(KEY_PORT, 50051),
        useTls       = prefs.getBoolean(KEY_TLS, false),
        apiToken     = prefs.getString(KEY_TOKEN, "")!!,
        agentId      = prefs.getString(KEY_AGENT_ID, null) ?: generateAndSaveId(),
    )

    fun save(config: AgentConfig) = prefs.edit {
        putString(KEY_HOST, config.backendHost)
        putInt(KEY_PORT, config.backendPort)
        putBoolean(KEY_TLS, config.useTls)
        putString(KEY_TOKEN, config.apiToken)
        putString(KEY_AGENT_ID, config.agentId)
    }

    private fun generateAndSaveId(): String {
        val id = "android-${UUID.randomUUID()}"
        prefs.edit { putString(KEY_AGENT_ID, id) }
        return id
    }

    companion object {
        private const val KEY_HOST     = "backend_host"
        private const val KEY_PORT     = "backend_port"
        private const val KEY_TLS      = "use_tls"
        private const val KEY_TOKEN    = "api_token"
        private const val KEY_AGENT_ID = "agent_id"
    }
}
