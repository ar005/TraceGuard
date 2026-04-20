package com.traceguard.agent.events

import kotlinx.serialization.Serializable

@Serializable
data class LiveCommand(
    val commandId: String,
    val action:    String,
    val args:      List<String> = emptyList(),
    val timeout:   Int = 30,
)

@Serializable
data class LiveResult(
    val commandId: String,
    val agentId:   String,
    val status:    String,    // running, completed, error, timeout
    val exitCode:  Int = 0,
    val stdout:    String = "",
    val stderr:    String = "",
    val error:     String = "",
)
