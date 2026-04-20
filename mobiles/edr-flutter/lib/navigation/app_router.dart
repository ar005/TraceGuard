import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/auth/login_screen.dart';
import 'package:edr_flutter/dashboard/dashboard_screen.dart';
import 'package:edr_flutter/agents/agents_screen.dart';
import 'package:edr_flutter/agents/agent_detail_screen.dart';
import 'package:edr_flutter/alerts/alerts_screen.dart';
import 'package:edr_flutter/alerts/alert_detail_screen.dart';
import 'package:edr_flutter/incidents/incidents_screen.dart';
import 'package:edr_flutter/incidents/incident_detail_screen.dart';
import 'package:edr_flutter/events/events_screen.dart';
import 'package:edr_flutter/hunt/hunt_screen.dart';
import 'package:edr_flutter/live_response/live_response_screen.dart';
import 'package:edr_flutter/settings/settings_screen.dart';

final routerProvider = Provider<GoRouter>((ref) {
  final authState = ref.watch(authProvider);

  return GoRouter(
    initialLocation: '/dashboard',
    redirect: (context, state) {
      final loggedIn = authState.status == AuthStatus.authenticated;
      final onLogin  = state.matchedLocation == '/login';

      if (!loggedIn && !onLogin) return '/login';
      if (loggedIn && onLogin)  return '/dashboard';
      return null;
    },
    routes: [
      GoRoute(
        path: '/login',
        builder: (_, __) => const LoginScreen(),
      ),

      // Shell with persistent bottom nav / rail
      ShellRoute(
        builder: (context, state, child) => _Shell(child: child),
        routes: [
          GoRoute(
            path: '/dashboard',
            builder: (_, __) => const DashboardScreen(),
          ),
          GoRoute(
            path: '/agents',
            builder: (_, __) => const AgentsScreen(),
            routes: [
              GoRoute(
                path: ':id',
                builder: (_, state) =>
                    AgentDetailScreen(agentId: state.pathParameters['id']!),
              ),
            ],
          ),
          GoRoute(
            path: '/alerts',
            builder: (_, __) => const AlertsScreen(),
            routes: [
              GoRoute(
                path: ':id',
                builder: (_, state) =>
                    AlertDetailScreen(alertId: state.pathParameters['id']!),
              ),
            ],
          ),
          GoRoute(
            path: '/incidents',
            builder: (_, __) => const IncidentsScreen(),
            routes: [
              GoRoute(
                path: ':id',
                builder: (_, state) =>
                    IncidentDetailScreen(incidentId: state.pathParameters['id']!),
              ),
            ],
          ),
          GoRoute(
            path: '/events',
            builder: (_, __) => const EventsScreen(),
          ),
          GoRoute(
            path: '/hunt',
            builder: (_, __) => const HuntScreen(),
          ),
          GoRoute(
            path: '/live-response',
            builder: (_, __) => const LiveResponseScreen(),
          ),
          GoRoute(
            path: '/settings',
            builder: (_, __) => const SettingsScreen(),
          ),
        ],
      ),
    ],
  );
});

class _Shell extends ConsumerWidget {
  final Widget child;
  const _Shell({required this.child});

  static const _tabs = [
    (path: '/dashboard',     icon: Icons.dashboard_outlined,    label: 'Dashboard'),
    (path: '/agents',        icon: Icons.devices_outlined,       label: 'Agents'),
    (path: '/alerts',        icon: Icons.warning_amber_outlined, label: 'Alerts'),
    (path: '/incidents',     icon: Icons.security_outlined,      label: 'Incidents'),
    (path: '/events',        icon: Icons.stream_outlined,        label: 'Events'),
    (path: '/hunt',          icon: Icons.search_outlined,        label: 'Hunt'),
    (path: '/live-response', icon: Icons.terminal_outlined,      label: 'Live'),
    (path: '/settings',      icon: Icons.settings_outlined,      label: 'Settings'),
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final location = GoRouterState.of(context).matchedLocation;
    final idx = _tabs.indexWhere((t) => location.startsWith(t.path));
    final selected = idx < 0 ? 0 : idx;

    // NavigationRail on wide screens, NavigationBar on narrow
    final isWide = MediaQuery.of(context).size.width >= 600;

    if (isWide) {
      return Scaffold(
        body: Row(children: [
          NavigationRail(
            selectedIndex: selected,
            onDestinationSelected: (i) => context.go(_tabs[i].path),
            labelType: NavigationRailLabelType.all,
            destinations: _tabs.map((t) => NavigationRailDestination(
              icon: Icon(t.icon),
              label: Text(t.label),
            )).toList(),
          ),
          const VerticalDivider(width: 1),
          Expanded(child: child),
        ]),
      );
    }

    return Scaffold(
      body: child,
      bottomNavigationBar: NavigationBar(
        selectedIndex: selected,
        onDestinationSelected: (i) => context.go(_tabs[i].path),
        destinations: _tabs.map((t) => NavigationDestination(
          icon: Icon(t.icon),
          label: t.label,
        )).toList(),
      ),
    );
  }
}
