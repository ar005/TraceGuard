package com.traceguard.agent.android.transport

import android.content.Context
import com.google.protobuf.ByteString
import com.traceguard.agent.agent.HeartbeatStats
import com.traceguard.agent.config.AgentConfig
import com.traceguard.agent.events.EventEnvelope
import com.traceguard.agent.events.LiveCommand
import com.traceguard.agent.events.LiveResult
import com.traceguard.agent.proto.EventServiceGrpcKt
import com.traceguard.agent.proto.RegisterRequest
import com.traceguard.agent.proto.HeartbeatRequest
import com.traceguard.agent.proto.AgentStats
import com.traceguard.agent.proto.LiveResult as ProtoLiveResult
import com.traceguard.agent.transport.Transport
import io.grpc.ManagedChannel
import io.grpc.android.AndroidChannelBuilder
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.receiveAsFlow

class GrpcTransport(
    private val config:  AgentConfig,
    private val context: Context,
) : Transport {

    private var channel: ManagedChannel?                                        = null
    private var stub:    EventServiceGrpcKt.EventServiceCoroutineStub? = null
    private var _connected = false

    override suspend fun connect(): Result<Unit> = runCatching {
        channel?.shutdown()
        val builder = AndroidChannelBuilder
            .forAddress(config.backendHost, config.backendPort)
            .context(context)
        if (!config.useTls) builder.usePlaintext()
        channel    = builder.build()
        stub       = EventServiceGrpcKt.EventServiceCoroutineStub(channel!!)
        _connected = true
    }.onFailure { _connected = false }

    override suspend fun sendEventBatch(events: List<EventEnvelope>): Result<Unit> =
        runCatching {
            val s = stub ?: error("not connected")
            s.streamEvents(flow { events.forEach { emit(it.toProto()) } })
        }.onFailure { _connected = false }

    override fun isConnected(): Boolean = _connected && channel?.isShutdown == false

    override fun disconnect() {
        channel?.shutdown()
        _connected = false
    }

    // ── Registration ──────────────────────────────────────────────────────────

    suspend fun register(hostname: String, ip: String, osVersion: String): Result<String> =
        runCatching {
            val s = stub ?: error("not connected")
            val resp = s.register(
                RegisterRequest.newBuilder()
                    .setAgentId(config.agentId)
                    .setHostname(hostname)
                    .setOs("android")
                    .setOsVersion(osVersion)
                    .setAgentVer(config.agentVersion)
                    .setIp(ip)
                    .build()
            )
            resp.assignedId
        }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    suspend fun heartbeat(hostname: String, stats: HeartbeatStats): Result<String> =
        runCatching {
            val s = stub ?: error("not connected")
            val resp = s.heartbeat(
                HeartbeatRequest.newBuilder()
                    .setAgentId(config.agentId)
                    .setHostname(hostname)
                    .setTimestamp(System.nanoTime())
                    .setAgentVer(config.agentVersion)
                    .setOs("android")
                    .setStats(
                        AgentStats.newBuilder()
                            .setEventsSent(stats.eventsSent)
                            .setEventsDropped(stats.eventsDropped)
                            .setBufferSize(stats.bufferSize)
                            .build()
                    )
                    .build()
            )
            resp.configVersion
        }

    // ── Live Response ─────────────────────────────────────────────────────────

    suspend fun openLiveResponse(
        resultChannel: Channel<ProtoLiveResult>,
        onCommand: suspend (LiveCommand) -> LiveResult,
    ) {
        val s = stub ?: error("not connected")
        val commandFlow = s.liveResponse(resultChannel.receiveAsFlow())
        commandFlow.collect { protoCmd ->
            val result = onCommand(protoCmd.toModel())
            resultChannel.trySend(result.toProto(config.agentId))
        }
    }
}

// ── Proto conversions ─────────────────────────────────────────────────────────

private fun EventEnvelope.toProto() =
    com.traceguard.agent.proto.EventEnvelope.newBuilder()
        .setAgentId(agentId)
        .setHostname(hostname)
        .setEventId(eventId)
        .setEventType(eventType)
        .setTimestamp(timestamp)
        .setPayload(ByteString.copyFromUtf8(payload))
        .setOs(os)
        .setAgentVer(agentVer)
        .build()

private fun com.traceguard.agent.proto.LiveCommand.toModel() = LiveCommand(
    commandId = commandId,
    action    = action,
    args      = argsList,
    timeout   = timeout,
)

private fun LiveResult.toProto(agentId: String) = ProtoLiveResult.newBuilder()
    .setCommandId(commandId)
    .setAgentId(agentId)
    .setStatus(status)
    .setExitCode(exitCode)
    .setStdout(stdout)
    .setStderr(stderr)
    .setError(error)
    .build()
