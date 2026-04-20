package com.traceguard.agent.android.buffer

import androidx.room.*

@Dao
interface EventDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(events: List<EventEntity>)

    @Query("SELECT * FROM events ORDER BY createdAt ASC LIMIT :limit")
    suspend fun peek(limit: Int): List<EventEntity>

    @Query("DELETE FROM events WHERE eventId IN (:ids)")
    suspend fun deleteByIds(ids: List<String>)

    @Query("SELECT COUNT(*) FROM events")
    suspend fun count(): Long

    @Query("""
        DELETE FROM events WHERE eventId IN
        (SELECT eventId FROM events ORDER BY createdAt ASC LIMIT :count)
    """)
    suspend fun deleteOldest(count: Int)
}
