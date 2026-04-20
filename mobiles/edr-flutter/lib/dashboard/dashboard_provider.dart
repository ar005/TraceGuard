import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Dashboard Stats Provider
// ---------------------------------------------------------------------------

class DashboardNotifier extends AsyncNotifier<DashboardStats> {
  @override
  Future<DashboardStats> build() async {
    return _load();
  }

  Future<DashboardStats> _load() async {
    final api = ref.read(edrApiProvider);
    return api.getDashboard();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => _load());
  }
}

final dashboardProvider =
    AsyncNotifierProvider<DashboardNotifier, DashboardStats>(
  DashboardNotifier.new,
);

// ---------------------------------------------------------------------------
// Recent alerts for dashboard (last 5)
// ---------------------------------------------------------------------------

final recentAlertsProvider = FutureProvider<List<Alert>>((ref) async {
  final api = ref.read(edrApiProvider);
  final alerts = await api.getAlerts(limit: 5);
  // Sort by createdAt descending and take first 5
  alerts.sort((a, b) => b.createdAt.compareTo(a.createdAt));
  return alerts.take(5).toList();
});
