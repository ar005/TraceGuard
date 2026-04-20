package com.traceguard.agent.android.buffer

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "events")
data class EventEntity(
    @PrimaryKey val eventId:   String,
    val agentId:   String,
    val hostname:  String,
    val eventType: String,
    val timestamp: Long,
    val payload:   String,
    val os:        String,
    val agentVer:  String,
    val createdAt: Long = System.currentTimeMillis(),
)
