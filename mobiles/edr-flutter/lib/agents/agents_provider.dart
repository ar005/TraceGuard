import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Agents list notifier
// ---------------------------------------------------------------------------

class AgentsNotifier extends AsyncNotifier<List<Agent>> {
  @override
  Future<List<Agent>> build() async {
    return _load();
  }

  Future<List<Agent>> _load() async {
    final api = ref.read(edrApiProvider);
    return api.getAgents();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => _load());
  }
}

final agentsProvider =
    AsyncNotifierProvider<AgentsNotifier, List<Agent>>(AgentsNotifier.new);

// ---------------------------------------------------------------------------
// Selected agent ID (for navigation / detail views)
// ---------------------------------------------------------------------------

final selectedAgentIdProvider = StateProvider<String?>((ref) => null);

// ---------------------------------------------------------------------------
// Agent detail (family by agent ID)
// ---------------------------------------------------------------------------

final agentDetailProvider =
    FutureProvider.family<Agent, String>((ref, agentId) async {
  final api = ref.read(edrApiProvider);
  return api.getAgent(agentId);
});
