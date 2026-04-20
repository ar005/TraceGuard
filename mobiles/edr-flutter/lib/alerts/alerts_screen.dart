import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:edr_flutter/alerts/alerts_provider.dart';
import 'package:edr_flutter/models/models.dart';

class AlertsScreen extends ConsumerWidget {
  /// When provided, filters alerts to this agent only (used in AgentDetailScreen).
  final String? agentIdFilter;

  const AlertsScreen({super.key, this.agentIdFilter});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Apply agentId filter if coming from AgentDetailScreen
    if (agentIdFilter != null) {
      final current = ref.read(alertFilterProvider);
      if (current.agentId != agentIdFilter) {
        // schedule for next frame to avoid modifying state during build
        Future.microtask(() {
          ref.read(alertFilterProvider.notifier).state =
              current.copyWith(agentId: agentIdFilter);
        });
      }
    }

    final filter = ref.watch(alertFilterProvider);
    final alertsAsync = ref.watch(alertsProvider);
    final colorScheme = Theme.of(context).colorScheme;

    final bool isEmbedded = agentIdFilter != null;

    Widget body = Column(
      children: [
        _FilterBar(filter: filter),
        Expanded(
          child: RefreshIndicator(
            onRefresh: () => ref.read(alertsProvider.notifier).refresh(),
            child: alertsAsync.when(
              data: (alerts) => alerts.isEmpty
                  ? _buildEmpty(context)
                  : _buildList(context, alerts),
              loading: () =>
                  const Center(child: CircularProgressIndicator()),
              error: (err, _) => _buildError(context, ref, err.toString()),
            ),
          ),
        ),
      ],
    );

    if (isEmbedded) return body;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Alerts'),
        centerTitle: false,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            tooltip: 'Refresh',
            onPressed: () => ref.read(alertsProvider.notifier).refresh(),
          ),
        ],
      ),
      body: body,
    );
  }

  Widget _buildList(BuildContext context, List<Alert> alerts) {
    return ListView.separated(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      itemCount: alerts.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (context, index) => _AlertTile(alert: alerts[index]),
    );
  }

  Widget _buildEmpty(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.notifications_none_outlined,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          const Text('No alerts found'),
          const SizedBox(height: 8),
          Text(
            'Try adjusting the filters.',
            style: TextStyle(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildError(BuildContext context, WidgetRef ref, String error) {
    final colorScheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline, size: 48, color: colorScheme.error),
            const SizedBox(height: 16),
            Text('Failed to load alerts',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error,
                textAlign: TextAlign.center,
                style: TextStyle(color: colorScheme.onSurfaceVariant)),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: () => ref.read(alertsProvider.notifier).refresh(),
              icon: const Icon(Icons.refresh),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

class _FilterBar extends ConsumerWidget {
  final AlertFilter filter;

  const _FilterBar({required this.filter});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final colorScheme = Theme.of(context).colorScheme;

    final severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    final statuses = ['ALL', 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'];

    return Container(
      color: colorScheme.surface,
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: severities.map((sev) {
                final isSelected = filter.severity == sev;
                final color = _severityColor(sev);
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: FilterChip(
                    label: Text(sev),
                    selected: isSelected,
                    selectedColor: color.withOpacity(0.2),
                    checkmarkColor: color,
                    labelStyle: TextStyle(
                      color: isSelected ? color : colorScheme.onSurfaceVariant,
                      fontSize: 12,
                      fontWeight: isSelected
                          ? FontWeight.w600
                          : FontWeight.normal,
                    ),
                    onSelected: (_) {
                      ref.read(alertFilterProvider.notifier).state =
                          filter.copyWith(severity: sev);
                    },
                  ),
                );
              }).toList(),
            ),
          ),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: statuses.map((st) {
                final isSelected = filter.status == st;
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: FilterChip(
                    label: Text(st),
                    selected: isSelected,
                    onSelected: (_) {
                      ref.read(alertFilterProvider.notifier).state =
                          filter.copyWith(status: st);
                    },
                  ),
                );
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }

  Color _severityColor(String severity) {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return const Color(0xFFF44336);
      case 'HIGH':
        return const Color(0xFFFF9800);
      case 'MEDIUM':
        return const Color(0xFFFFC107);
      case 'LOW':
        return const Color(0xFF2196F3);
      default:
        return const Color(0xFF9E9E9E);
    }
  }
}

// ---------------------------------------------------------------------------
// Alert tile
// ---------------------------------------------------------------------------

class _AlertTile extends StatelessWidget {
  final Alert alert;

  const _AlertTile({required this.alert});

  Color _severityColor() {
    switch (alert.severity.toUpperCase()) {
      case 'CRITICAL':
        return const Color(0xFFF44336);
      case 'HIGH':
        return const Color(0xFFFF9800);
      case 'MEDIUM':
        return const Color(0xFFFFC107);
      default:
        return const Color(0xFF2196F3);
    }
  }

  String _timeAgo(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inSeconds < 60) return '${diff.inSeconds}s ago';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final sevColor = _severityColor();

    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: sevColor.withOpacity(0.25)),
      ),
      clipBehavior: Clip.antiAlias,
      child: ListTile(
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        leading: Container(
          width: 4,
          height: 40,
          decoration: BoxDecoration(
            color: sevColor,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
        title: Text(
          alert.ruleName,
          style: textTheme.bodyLarge?.copyWith(
            fontWeight: FontWeight.w600,
            color: colorScheme.onSurface,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: sevColor.withOpacity(0.15),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                alert.severity.toUpperCase(),
                style: textTheme.labelSmall?.copyWith(
                  color: sevColor,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                _timeAgo(alert.createdAt),
                style: textTheme.bodySmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
        trailing: Chip(
          label: Text(
            alert.status.toUpperCase(),
            style: const TextStyle(fontSize: 10),
          ),
          padding: EdgeInsets.zero,
          labelPadding:
              const EdgeInsets.symmetric(horizontal: 6, vertical: -2),
        ),
        onTap: () => context.push('/alerts/${alert.id}'),
      ),
    );
  }
}
