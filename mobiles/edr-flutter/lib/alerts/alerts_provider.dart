import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Filter state
// ---------------------------------------------------------------------------

class AlertFilter {
  final String severity; // 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  final String status; // 'ALL' | 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED'
  final String? agentId;

  const AlertFilter({
    this.severity = 'ALL',
    this.status = 'ALL',
    this.agentId,
  });

  AlertFilter copyWith({
    String? severity,
    String? status,
    String? agentId,
    bool clearAgentId = false,
  }) {
    return AlertFilter(
      severity: severity ?? this.severity,
      status: status ?? this.status,
      agentId: clearAgentId ? null : (agentId ?? this.agentId),
    );
  }
}

final alertFilterProvider =
    StateProvider<AlertFilter>((ref) => const AlertFilter());

// ---------------------------------------------------------------------------
// Alerts notifier
// ---------------------------------------------------------------------------

class AlertsNotifier extends AsyncNotifier<List<Alert>> {
  @override
  Future<List<Alert>> build() async {
    // Re-run when filter changes
    final filter = ref.watch(alertFilterProvider);
    return _load(filter);
  }

  Future<List<Alert>> _load(AlertFilter filter) async {
    final api = ref.read(edrApiProvider);
    return api.getAlerts(
      agentId: filter.agentId,
      severity: filter.severity == 'ALL' ? null : filter.severity,
      status: filter.status == 'ALL' ? null : filter.status,
    );
  }

  Future<void> refresh() async {
    final filter = ref.read(alertFilterProvider);
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => _load(filter));
  }

  Future<void> updateStatus(String alertId, String newStatus) async {
    final api = ref.read(edrApiProvider);
    await api.updateAlertStatus(alertId, newStatus);
    await refresh();
  }
}

final alertsProvider =
    AsyncNotifierProvider<AlertsNotifier, List<Alert>>(AlertsNotifier.new);

// ---------------------------------------------------------------------------
// Selected alert
// ---------------------------------------------------------------------------

final selectedAlertIdProvider = StateProvider<String?>((ref) => null);

// ---------------------------------------------------------------------------
// Alert detail
// ---------------------------------------------------------------------------

final alertDetailProvider =
    FutureProvider.family<Alert, String>((ref, alertId) async {
  final api = ref.read(edrApiProvider);
  return api.getAlert(alertId);
});
