package com.traceguard.agent.android.monitor

import android.app.ActivityManager
import android.content.Context
import com.traceguard.agent.android.util.buildEnvelope
import com.traceguard.agent.config.AgentConfig
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.EventTypes
import com.traceguard.agent.events.ProcessEntry
import com.traceguard.agent.events.ProcessListPayload
import com.traceguard.agent.monitor.Monitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

// NOTE: On Android 11+ (API 30+), getRunningAppProcesses() returns only the calling
// app's own process due to process visibility restrictions. This is a platform
// limitation — root or shell access is required for a full process list on modern Android.
class ProcessMonitor(
    private val context: Context,
    private val config:  AgentConfig,
) : Monitor {
    override val name = "ProcessMonitor"

    private val am  = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    private var job: kotlinx.coroutines.Job? = null

    override fun start(scope: CoroutineScope, emit: suspend (EventEnvelope) -> Unit) {
        job = scope.launch {
            while (isActive) {
                emit(buildProcessListEvent())
                delay(config.processListIntervalSeconds * 1_000L)
            }
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
    }

    private fun buildProcessListEvent(): EventEnvelope {
        val procs = am.runningAppProcesses ?: emptyList()
        val entries = procs.map { p ->
            ProcessEntry(
                pid           = p.pid,
                processName   = p.processName,
                importance    = p.importance,
                importanceStr = importanceLabel(p.importance),
                uid           = p.uid,
            )
        }
        val payload = ProcessListPayload(processes = entries)
        return buildEnvelope(EventTypes.PROCESS_LIST, Json.encodeToString(payload))
    }

    private fun importanceLabel(importance: Int): String = when (importance) {
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND         -> "FOREGROUND"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE -> "FG_SERVICE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE            -> "VISIBLE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_PERCEPTIBLE        -> "PERCEPTIBLE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE            -> "SERVICE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED             -> "CACHED"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE               -> "GONE"
        else                                                                 -> "UNKNOWN($importance)"
    }
}
