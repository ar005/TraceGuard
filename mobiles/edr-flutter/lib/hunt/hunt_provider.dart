import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Hunt State
// ---------------------------------------------------------------------------

class HuntState {
  final HuntResult? result;
  final bool isLoading;
  final String? error;
  final String query;

  const HuntState({
    this.result,
    this.isLoading = false,
    this.error,
    this.query = '',
  });

  HuntState copyWith({
    HuntResult? result,
    bool? isLoading,
    String? error,
    String? query,
    bool clearError = false,
    bool clearResult = false,
  }) {
    return HuntState(
      result: clearResult ? null : (result ?? this.result),
      isLoading: isLoading ?? this.isLoading,
      error: clearError ? null : (error ?? this.error),
      query: query ?? this.query,
    );
  }
}

// ---------------------------------------------------------------------------
// Hunt Notifier
// ---------------------------------------------------------------------------

class HuntNotifier extends StateNotifier<HuntState> {
  final Ref _ref;

  HuntNotifier(this._ref) : super(const HuntState());

  Future<void> runQuery(String query) async {
    if (query.trim().isEmpty) return;

    state = state.copyWith(
      isLoading: true,
      query: query,
      clearError: true,
    );

    try {
      final api = _ref.read(edrApiProvider);
      final result = await api.hunt(query.trim());
      state = state.copyWith(
        result: result,
        isLoading: false,
      );
    } on Exception catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString().replaceFirst('Exception: ', ''),
        clearResult: true,
      );
    }
  }

  void clearResults() {
    state = const HuntState();
  }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

final huntProvider = StateNotifierProvider<HuntNotifier, HuntState>((ref) {
  return HuntNotifier(ref);
});

// ---------------------------------------------------------------------------
// Query templates
// ---------------------------------------------------------------------------

class QueryTemplate {
  final String name;
  final String description;
  final String query;

  const QueryTemplate({
    required this.name,
    required this.description,
    required this.query,
  });
}

const List<QueryTemplate> kQueryTemplates = [
  QueryTemplate(
    name: 'Recent process events',
    description: 'Last 100 process creation events',
    query: 'SELECT * FROM events WHERE event_type = \'process\' ORDER BY timestamp DESC LIMIT 100',
  ),
  QueryTemplate(
    name: 'Failed connections last hour',
    description: 'Network connections that failed in the last hour',
    query: 'SELECT * FROM events WHERE event_type = \'network\' AND timestamp > NOW() - INTERVAL \'1 hour\' ORDER BY timestamp DESC',
  ),
  QueryTemplate(
    name: 'App installs today',
    description: 'Package/module install events today',
    query: 'SELECT * FROM events WHERE event_type = \'module\' AND timestamp > NOW() - INTERVAL \'24 hours\' ORDER BY timestamp DESC',
  ),
  QueryTemplate(
    name: 'DNS lookups to rare domains',
    description: 'DNS queries sorted by count (rarest first)',
    query: 'SELECT hostname, COUNT(*) as count FROM events WHERE event_type = \'dns\' GROUP BY hostname ORDER BY count ASC LIMIT 50',
  ),
  QueryTemplate(
    name: 'Auth events last 24h',
    description: 'Authentication events in the last 24 hours',
    query: 'SELECT * FROM events WHERE event_type = \'auth\' AND timestamp > NOW() - INTERVAL \'24 hours\' ORDER BY timestamp DESC',
  ),
  QueryTemplate(
    name: 'Agents with most events',
    description: 'Top agents by event volume',
    query: 'SELECT agent_id, COUNT(*) as event_count FROM events GROUP BY agent_id ORDER BY event_count DESC',
  ),
  QueryTemplate(
    name: 'File write events',
    description: 'File modification/creation events',
    query: 'SELECT * FROM events WHERE event_type = \'file\' ORDER BY timestamp DESC LIMIT 200',
  ),
  QueryTemplate(
    name: 'Syscall events by type',
    description: 'Syscall events grouped by call name',
    query: 'SELECT event_type, COUNT(*) as count FROM events WHERE event_type = \'syscall\' GROUP BY event_type ORDER BY count DESC',
  ),
];
