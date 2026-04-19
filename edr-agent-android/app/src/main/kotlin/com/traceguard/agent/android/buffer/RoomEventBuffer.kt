package com.traceguard.agent.android.buffer

import com.traceguard.agent.buffer.EventBuffer
import com.traceguard.agent.events.EventEnvelope

class RoomEventBuffer(db: EventDatabase) : EventBuffer {
    private val dao = db.eventDao()

    override suspend fun insert(event: EventEnvelope) = insertBatch(listOf(event))

    override suspend fun insertBatch(events: List<EventEnvelope>) =
        dao.insertAll(events.map { it.toEntity() })

    override suspend fun peek(limit: Int): List<EventEnvelope> =
        dao.peek(limit).map { it.toEnvelope() }

    override suspend fun delete(eventIds: List<String>) = dao.deleteByIds(eventIds)

    override suspend fun count(): Long = dao.count()

    override suspend fun pruneOldest(keepCount: Int) {
        val excess = dao.count() - keepCount
        if (excess > 0) dao.deleteOldest(excess.toInt())
    }
}

private fun EventEnvelope.toEntity() = EventEntity(
    eventId   = eventId,
    agentId   = agentId,
    hostname  = hostname,
    eventType = eventType,
    timestamp = timestamp,
    payload   = payload,
    os        = os,
    agentVer  = agentVer,
)

private fun EventEntity.toEnvelope() = EventEnvelope(
    eventId   = eventId,
    agentId   = agentId,
    hostname  = hostname,
    eventType = eventType,
    timestamp = timestamp,
    payload   = payload,
    os        = os,
    agentVer  = agentVer,
)
