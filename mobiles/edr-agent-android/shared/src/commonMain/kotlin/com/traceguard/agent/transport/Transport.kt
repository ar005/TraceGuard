package com.traceguard.agent.transport

import com.traceguard.agent.events.EventEnvelope

interface Transport {
    suspend fun connect(): Result<Unit>
    suspend fun sendEventBatch(events: List<EventEnvelope>): Result<Unit>
    fun isConnected(): Boolean
    fun disconnect()
}
