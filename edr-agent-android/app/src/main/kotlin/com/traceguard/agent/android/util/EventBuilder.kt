package com.traceguard.agent.android.util

import com.traceguard.agent.events.EventEnvelope
import java.util.UUID

private var _agentId  = ""
private var _hostname = ""

fun initEventBuilder(agentId: String, hostname: String) {
    _agentId  = agentId
    _hostname = hostname
}

fun buildEnvelope(eventType: String, payload: String): EventEnvelope = EventEnvelope(
    agentId   = _agentId,
    hostname  = _hostname,
    eventId   = UUID.randomUUID().toString(),
    eventType = eventType,
    timestamp = System.nanoTime(),
    payload   = payload,
    os        = "android",
    agentVer  = "1.0.0",
)
