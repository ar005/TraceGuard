import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Incidents list
// ---------------------------------------------------------------------------

class IncidentsNotifier extends AsyncNotifier<List<Incident>> {
  @override
  Future<List<Incident>> build() async {
    return _load();
  }

  Future<List<Incident>> _load() async {
    final api = ref.read(edrApiProvider);
    return api.getIncidents();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => _load());
  }
}

final incidentsProvider =
    AsyncNotifierProvider<IncidentsNotifier, List<Incident>>(
  IncidentsNotifier.new,
);

// ---------------------------------------------------------------------------
// Incident detail (family)
// ---------------------------------------------------------------------------

final incidentDetailProvider =
    FutureProvider.family<Incident, String>((ref, incidentId) async {
  final api = ref.read(edrApiProvider);
  return api.getIncident(incidentId);
});

// ---------------------------------------------------------------------------
// Selected incident
// ---------------------------------------------------------------------------

final selectedIncidentIdProvider = StateProvider<String?>((ref) => null);
