package com.traceguard.agent.agent

import com.traceguard.agent.config.AgentConfig

class Registration(private val config: AgentConfig) {
    private var registered  = false
    private var assignedId  = ""
    private var configVer   = ""

    fun onRegistered(assignedId: String, configVersion: String) {
        this.assignedId = assignedId.ifBlank { config.agentId }
        this.configVer  = configVersion
        this.registered = true
    }

    fun reset() {
        registered = false
    }

    fun isRegistered(): Boolean = registered
    fun agentId(): String       = assignedId.ifBlank { config.agentId }
    fun configVersion(): String = configVer
}
