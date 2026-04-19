package com.traceguard.agent.monitor

import com.traceguard.agent.events.EventEnvelope
import kotlinx.coroutines.CoroutineScope

interface Monitor {
    val name: String
    fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit)
    fun stop()
}
