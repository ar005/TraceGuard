package com.traceguard.agent.agent

data class HeartbeatStats(
    val eventsSent:    Long = 0,
    val eventsDropped: Long = 0,
    val bufferSize:    Long = 0,
)

class HeartbeatTracker {
    private var sent    = 0L
    private var dropped = 0L

    fun recordSent(count: Long = 1)    { sent    += count }
    fun recordDropped(count: Long = 1) { dropped += count }

    fun snapshot(bufferSize: Long) = HeartbeatStats(
        eventsSent    = sent,
        eventsDropped = dropped,
        bufferSize    = bufferSize,
    )
}
