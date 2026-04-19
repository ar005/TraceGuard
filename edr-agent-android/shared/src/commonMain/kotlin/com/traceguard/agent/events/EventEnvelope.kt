package com.traceguard.agent.events

import kotlinx.serialization.Serializable

@Serializable
data class EventEnvelope(
    val agentId:   String,
    val hostname:  String,
    val eventId:   String,
    val eventType: String,
    val timestamp: Long,        // Unix nanoseconds
    val payload:   String,      // JSON-encoded typed payload
    val os:        String = "android",
    val agentVer:  String = "1.0.0",
)
