import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:edr_flutter/alerts/alerts_provider.dart';
import 'package:edr_flutter/incidents/incidents_provider.dart';
import 'package:edr_flutter/models/models.dart';

class IncidentDetailScreen extends ConsumerWidget {
  final String incidentId;

  const IncidentDetailScreen({super.key, required this.incidentId});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final incidentAsync = ref.watch(incidentDetailProvider(incidentId));
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Incident Detail'),
        leading: BackButton(onPressed: () => context.pop()),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            onPressed: () =>
                ref.invalidate(incidentDetailProvider(incidentId)),
          ),
        ],
      ),
      body: incidentAsync.when(
        data: (incident) => _buildContent(context, ref, incident),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => _buildError(context, ref, err.toString()),
      ),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    Incident incident,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final sevColor = _severityColor(incident.severity);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Header
        Row(
          children: [
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: sevColor.withOpacity(0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: sevColor.withOpacity(0.4)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.layers_outlined, size: 16, color: sevColor),
                  const SizedBox(width: 6),
                  Text(
                    incident.severity.toUpperCase(),
                    style: textTheme.labelMedium?.copyWith(
                      color: sevColor,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 10),
            Chip(
              label: Text(
                incident.status.toUpperCase(),
                style: const TextStyle(fontSize: 12),
              ),
            ),
          ],
        ),

        const SizedBox(height: 16),

        Text(
          'Incident #${incident.id.substring(0, 8)}',
          style: textTheme.headlineSmall?.copyWith(
            color: colorScheme.onSurface,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          'Created ${_formatDate(incident.createdAt)}  ·  ${incident.alertCount} correlated alert${incident.alertCount != 1 ? 's' : ''}',
          style: textTheme.bodySmall
              ?.copyWith(color: colorScheme.onSurfaceVariant),
        ),

        const SizedBox(height: 20),

        // Details
        _SectionCard(
          title: 'Details',
          child: Column(
            children: [
              _Row(label: 'Incident ID', value: incident.id, mono: true),
              _Row(label: 'Agent ID', value: incident.agentId, mono: true),
              _Row(label: 'Severity', value: incident.severity.toUpperCase()),
              _Row(
                label: 'Status',
                value: incident.status.toUpperCase(),
                isLast: true,
              ),
            ],
          ),
        ),

        const SizedBox(height: 16),

        // MITRE IDs
        if (incident.mitreIds.isNotEmpty) ...[
          _SectionCard(
            title: 'MITRE ATT&CK',
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: incident.mitreIds.map((id) {
                return Chip(
                  label: Text(id),
                  backgroundColor:
                      colorScheme.secondaryContainer.withOpacity(0.7),
                  labelStyle: TextStyle(
                    color: colorScheme.onSecondaryContainer,
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // Correlated alerts
        if (incident.alertIds.isNotEmpty) ...[
          Text(
            'Correlated Alerts',
            style: textTheme.titleSmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
            ),
          ),
          const SizedBox(height: 10),
          ...incident.alertIds.map(
            (alertId) => _CorrelatedAlertTile(alertId: alertId),
          ),
        ],
      ],
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
      default:
        return const Color(0xFF2196F3);
    }
  }

  String _formatDate(DateTime dt) {
    final local = dt.toLocal();
    return '${local.year}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')} '
        '${local.hour.toString().padLeft(2, '0')}:${local.minute.toString().padLeft(2, '0')}';
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
            Text('Failed to load incident',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error,
                textAlign: TextAlign.center,
                style: TextStyle(color: colorScheme.onSurfaceVariant)),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: () =>
                  ref.invalidate(incidentDetailProvider(incidentId)),
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
// Correlated alert tile (fetches alert detail individually)
// ---------------------------------------------------------------------------

class _CorrelatedAlertTile extends ConsumerWidget {
  final String alertId;

  const _CorrelatedAlertTile({required this.alertId});

  Color _severityColor(String severity) {
    switch (severity.toUpperCase()) {
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

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final alertAsync = ref.watch(alertDetailProvider(alertId));
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: alertAsync.when(
        data: (alert) {
          final sevColor = _severityColor(alert.severity);
          return Card(
            elevation: 0,
            color: colorScheme.surfaceContainerHigh,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(10),
              side: BorderSide(color: sevColor.withOpacity(0.25)),
            ),
            child: ListTile(
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
              leading: Container(
                width: 4,
                height: 36,
                decoration: BoxDecoration(
                  color: sevColor,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              title: Text(
                alert.ruleName,
                style: textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                  color: colorScheme.onSurface,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              subtitle: Text(
                '${alert.severity.toUpperCase()} · ${alert.status}',
                style: textTheme.bodySmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
              trailing: const Icon(Icons.chevron_right, size: 18),
              onTap: () => context.push('/alerts/${alert.id}'),
            ),
          );
        },
        loading: () => Card(
          elevation: 0,
          color: colorScheme.surfaceContainerHigh,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
          child: const SizedBox(
            height: 56,
            child: Center(
              child: SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ),
          ),
        ),
        error: (_, __) => Card(
          elevation: 0,
          color: colorScheme.surfaceContainerHigh,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
            side: BorderSide(color: colorScheme.outlineVariant.withOpacity(0.3)),
          ),
          child: ListTile(
            leading: Icon(Icons.warning_outlined, color: colorScheme.error),
            title: Text(
              'Alert $alertId',
              style: textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
            ),
            subtitle: Text(
              'Could not load details',
              style: TextStyle(color: colorScheme.onSurfaceVariant),
            ),
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Shared sub-widgets
// ---------------------------------------------------------------------------

class _SectionCard extends StatelessWidget {
  final String title;
  final Widget child;

  const _SectionCard({required this.title, required this.child});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    return Card(
      elevation: 0,
      color: colorScheme.surfaceContainerHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: colorScheme.outlineVariant.withOpacity(0.4)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: textTheme.labelSmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}

class _Row extends StatelessWidget {
  final String label;
  final String value;
  final bool mono;
  final bool isLast;

  const _Row({
    required this.label,
    required this.value,
    this.mono = false,
    this.isLast = false,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 100,
                child: Text(label,
                    style: textTheme.bodySmall
                        ?.copyWith(color: colorScheme.onSurfaceVariant)),
              ),
              Expanded(
                child: Text(
                  value,
                  style: textTheme.bodyMedium?.copyWith(
                    color: colorScheme.onSurface,
                    fontFamily: mono ? 'monospace' : null,
                  ),
                ),
              ),
            ],
          ),
        ),
        if (!isLast)
          Divider(
            height: 1,
            color: colorScheme.outlineVariant.withOpacity(0.3),
          ),
      ],
    );
  }
}
