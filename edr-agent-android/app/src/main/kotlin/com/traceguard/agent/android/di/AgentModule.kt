package com.traceguard.agent.android.di

import android.content.Context
import android.content.SharedPreferences
import androidx.room.Room
import com.traceguard.agent.android.buffer.EventDatabase
import com.traceguard.agent.android.buffer.RoomEventBuffer
import com.traceguard.agent.android.config.ConfigRepository
import com.traceguard.agent.android.transport.GrpcTransport
import com.traceguard.agent.buffer.EventBuffer
import com.traceguard.agent.config.AgentConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AgentModule {

    @Provides
    @Singleton
    fun provideSharedPreferences(@ApplicationContext ctx: Context): SharedPreferences =
        ctx.getSharedPreferences("traceguard_prefs", Context.MODE_PRIVATE)

    @Provides
    @Singleton
    fun provideAgentConfig(repo: ConfigRepository): AgentConfig = repo.load()

    @Provides
    @Singleton
    fun provideEventDatabase(@ApplicationContext ctx: Context): EventDatabase =
        Room.databaseBuilder(ctx, EventDatabase::class.java, "tg_events.db")
            .fallbackToDestructiveMigration()
            .build()

    @Provides
    @Singleton
    fun provideEventBuffer(db: EventDatabase): EventBuffer = RoomEventBuffer(db)

    @Provides
    @Singleton
    fun provideGrpcTransport(
        @ApplicationContext ctx: Context,
        config: AgentConfig,
    ): GrpcTransport = GrpcTransport(config, ctx)
}
