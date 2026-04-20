import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/app.dart';
import 'package:edr_flutter/auth/auth_provider.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Pre-load saved JWT so the router redirect sees auth state immediately
  final container = ProviderContainer();
  await container.read(authProvider.notifier).tryRestoreSession();

  runApp(
    UncontrolledProviderScope(
      container: container,
      child: const TraceGuardApp(),
    ),
  );
}
