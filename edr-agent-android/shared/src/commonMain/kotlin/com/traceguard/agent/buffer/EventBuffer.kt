package com.traceguard.agent.buffer

import com.traceguard.agent.events.EventEnvelope

interface EventBuffer {
    suspend fun insert(event: EventEnvelope)
    suspend fun insertBatch(events: List<EventEnvelope>)
    suspend fun peek(limit: Int): List<EventEnvelope>
    suspend fun delete(eventIds: List<String>)
    suspend fun count(): Long
    suspend fun pruneOldest(keepCount: Int)
}
