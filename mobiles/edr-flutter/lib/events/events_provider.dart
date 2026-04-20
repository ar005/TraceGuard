import 'dart:async';
import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Events state
// ---------------------------------------------------------------------------

class EventsState {
  final List<EventRecord> events;
  final bool isPaused;
  final bool isConnected;
  final String? agentIdFilter;
  final String? eventTypeFilter;
  final String? error;

  const EventsState({
    this.events = const [],
    this.isPaused = false,
    this.isConnected = false,
    this.agentIdFilter,
    this.eventTypeFilter,
    this.error,
  });

  EventsState copyWith({
    List<EventRecord>? events,
    bool? isPaused,
    bool? isConnected,
    String? agentIdFilter,
    String? eventTypeFilter,
    String? error,
    bool clearError = false,
    bool clearAgentFilter = false,
    bool clearEventTypeFilter = false,
  }) {
    return EventsState(
      events: events ?? this.events,
      isPaused: isPaused ?? this.isPaused,
      isConnected: isConnected ?? this.isConnected,
      agentIdFilter:
          clearAgentFilter ? null : (agentIdFilter ?? this.agentIdFilter),
      eventTypeFilter: clearEventTypeFilter
          ? null
          : (eventTypeFilter ?? this.eventTypeFilter),
      error: clearError ? null : (error ?? this.error),
    );
  }
}

// ---------------------------------------------------------------------------
// Events Notifier
// ---------------------------------------------------------------------------

const _kMaxEvents = 500;

class EventsNotifier extends StateNotifier<EventsState> {
  final Ref _ref;
  http.Client? _sseClient;
  StreamSubscription<String>? _sseSub;
  bool _disposed = false;

  EventsNotifier(this._ref) : super(const EventsState());

  @override
  void dispose() {
    _disposed = true;
    _closeSse();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // SSE connection
  // ---------------------------------------------------------------------------

  Future<void> connect() async {
    if (state.isConnected) return;

    try {
      final api = _ref.read(edrApiProvider);
      final ticket = await api.getSseTicket();
      if (_disposed) return;

      final backendUrl = _ref.read(backendUrlProvider);
      final uri = Uri.parse('$backendUrl/api/v1/events/stream?token=$ticket');

      _sseClient = http.Client();
      final request = http.Request('GET', uri);
      request.headers['Accept'] = 'text/event-stream';
      request.headers['Cache-Control'] = 'no-cache';

      // Read current token from auth state for auth header
      final token = _ref.read(authProvider).token;
      if (token != null && token.isNotEmpty) {
        request.headers['Authorization'] = 'Bearer $token';
      }

      final response = await _sseClient!.send(request);
      if (_disposed) {
        _sseClient?.close();
        return;
      }

      if (response.statusCode != 200) {
        state = state.copyWith(
          error: 'SSE connection failed: HTTP ${response.statusCode}',
        );
        return;
      }

      state = state.copyWith(isConnected: true, clearError: true);

      // Parse SSE stream
      final lineBuffer = StringBuffer();
      _sseSub = response.stream
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen(
        (line) {
          if (_disposed) return;
          if (state.isPaused) return;

          if (line.startsWith('data: ')) {
            final data = line.substring(6).trim();
            if (data.isNotEmpty) {
              _handleSseData(data);
            }
          } else if (line.isEmpty && lineBuffer.isNotEmpty) {
            lineBuffer.clear();
          }
        },
        onError: (error) {
          if (!_disposed) {
            state = state.copyWith(
              isConnected: false,
              error: 'Stream error: $error',
            );
          }
        },
        onDone: () {
          if (!_disposed) {
            state = state.copyWith(isConnected: false);
          }
        },
        cancelOnError: false,
      );
    } on Exception catch (e) {
      if (!_disposed) {
        state = state.copyWith(
          isConnected: false,
          error: 'Connection failed: ${e.toString().replaceFirst('Exception: ', '')}',
        );
      }
    }
  }

  void _handleSseData(String data) {
    try {
      final decoded = jsonDecode(data);
      if (decoded is Map<String, dynamic>) {
        final record = EventRecord.fromJson(decoded);

        // Apply filters
        if (state.agentIdFilter != null &&
            state.agentIdFilter!.isNotEmpty &&
            record.agentId != state.agentIdFilter) {
          return;
        }
        if (state.eventTypeFilter != null &&
            state.eventTypeFilter!.isNotEmpty &&
            record.eventType != state.eventTypeFilter) {
          return;
        }

        final updated = [record, ...state.events];
        // Cap at max
        if (updated.length > _kMaxEvents) {
          updated.removeRange(_kMaxEvents, updated.length);
        }
        state = state.copyWith(events: updated);
      }
    } catch (_) {
      // Ignore malformed frames
    }
  }

  void _closeSse() {
    _sseSub?.cancel();
    _sseSub = null;
    _sseClient?.close();
    _sseClient = null;
  }

  void disconnect() {
    _closeSse();
    state = state.copyWith(isConnected: false);
  }

  // ---------------------------------------------------------------------------
  // Controls
  // ---------------------------------------------------------------------------

  void togglePause() {
    state = state.copyWith(isPaused: !state.isPaused);
  }

  void setAgentIdFilter(String? agentId) {
    if (agentId == null || agentId.isEmpty) {
      state = state.copyWith(clearAgentFilter: true);
    } else {
      state = state.copyWith(agentIdFilter: agentId);
    }
  }

  void setEventTypeFilter(String? eventType) {
    if (eventType == null || eventType.isEmpty) {
      state = state.copyWith(clearEventTypeFilter: true);
    } else {
      state = state.copyWith(eventTypeFilter: eventType);
    }
  }

  void clearEvents() {
    state = state.copyWith(events: []);
  }

  // ---------------------------------------------------------------------------
  // Load historical events via REST (used when embedded in AgentDetailScreen)
  // ---------------------------------------------------------------------------

  Future<void> loadHistorical({
    String? agentId,
    String? eventType,
    int limit = 100,
  }) async {
    try {
      final api = _ref.read(edrApiProvider);
      final events = await api.getEvents(
        agentId: agentId,
        eventType: eventType,
        limit: limit,
      );
      state = state.copyWith(events: events, clearError: true);
    } on Exception catch (e) {
      state = state.copyWith(
        error: e.toString().replaceFirst('Exception: ', ''),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

final eventsProvider =
    StateNotifierProvider<EventsNotifier, EventsState>((ref) {
  return EventsNotifier(ref);
});

/// A separate provider for when events are embedded in AgentDetail
/// with a fixed agent filter (avoids sharing state with the live stream).
final agentEventsProvider =
    FutureProvider.family<List<EventRecord>, String>((ref, agentId) async {
  final api = ref.read(edrApiProvider);
  return api.getEvents(agentId: agentId, limit: 100);
});
