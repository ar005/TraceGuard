package com.traceguard.agent.config

data class AgentConfig(
    val backendHost:               String  = "192.168.1.100",
    val backendPort:               Int     = 50051,
    val useTls:                    Boolean = false,
    val apiToken:                  String  = "",
    val agentId:                   String  = "",
    val agentVersion:              String  = "1.0.0",
    val heartbeatIntervalSeconds:  Long    = 30,
    val flushIntervalSeconds:      Long    = 5,
    val bufferMaxRows:             Int     = 10_000,
    val vulnScanIntervalHours:     Int     = 6,
    val processListIntervalSeconds: Long   = 30,
)
