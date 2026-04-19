package com.traceguard.agent.agent

import com.traceguard.agent.buffer.EventBuffer
import com.traceguard.agent.config.AgentConfig
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.monitor.Monitor
import com.traceguard.agent.transport.Transport
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel

class AgentCore(
    private val config:    AgentConfig,
    private val transport: Transport,
    private val buffer:    EventBuffer,
    private val monitors:  List<Monitor>,
) {
    private val scope        = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val eventChannel = Channel<EventEnvelope>(capacity = Channel.BUFFERED)

    val heartbeatTracker = HeartbeatTracker()
    val registration     = Registration(config)

    fun start() {
        startMonitors()
        startBufferWriter()
        startFlusher()
    }

    fun stop() {
        monitors.forEach { it.stop() }
        eventChannel.close()
        scope.cancel()
    }

    fun enqueue(event: EventEnvelope) {
        if (!eventChannel.trySend(event).isSuccess) {
            heartbeatTracker.recordDropped()
        }
    }

    private fun startMonitors() {
        monitors.forEach { monitor ->
            monitor.start(scope) { event -> eventChannel.trySend(event) }
        }
    }

    private fun startBufferWriter() {
        scope.launch {
            for (event in eventChannel) {
                runCatching { buffer.insert(event) }
                    .onFailure { heartbeatTracker.recordDropped() }
            }
        }
    }

    private fun startFlusher() {
        scope.launch {
            while (isActive) {
                delay(config.flushIntervalSeconds * 1_000L)
                flush()
            }
        }
    }

    private suspend fun flush() {
        if (!transport.isConnected()) {
            transport.connect().getOrNull() ?: return
        }
        val batch = buffer.peek(100)
        if (batch.isEmpty()) return
        transport.sendEventBatch(batch).onSuccess {
            buffer.delete(batch.map { it.eventId })
            heartbeatTracker.recordSent(batch.size.toLong())
        }
        // Prune if buffer grows beyond limit
        if (buffer.count() > config.bufferMaxRows) {
            buffer.pruneOldest(config.bufferMaxRows)
        }
    }
}
