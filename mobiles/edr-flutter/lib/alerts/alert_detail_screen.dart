import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:edr_flutter/alerts/alerts_provider.dart';
import 'package:edr_flutter/models/models.dart';

class AlertDetailScreen extends ConsumerWidget {
  final String alertId;

  const AlertDetailScreen({super.key, required this.alertId});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final alertAsync = ref.watch(alertDetailProvider(alertId));
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Alert Detail'),
        leading: BackButton(onPressed: () => context.pop()),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            onPressed: () => ref.invalidate(alertDetailProvider(alertId)),
          ),
        ],
      ),
      body: alertAsync.when(
        data: (alert) => _buildContent(context, ref, alert),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => _buildError(context, ref, err.toString()),
      ),
    );
  }

  Widget _buildContent(BuildContext context, WidgetRef ref, Alert alert) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final sevColor = _severityColor(alert.severity);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Severity + status header
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: sevColor.withOpacity(0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: sevColor.withOpacity(0.4)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.warning_amber_outlined,
                      size: 16, color: sevColor),
                  const SizedBox(width: 6),
                  Text(
                    alert.severity.toUpperCase(),
                    style: textTheme.labelMedium?.copyWith(
                      color: sevColor,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 10),
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: colorScheme.surfaceContainerHigh,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                    color: colorScheme.outlineVariant.withOpacity(0.5)),
              ),
              child: Text(
                alert.status.toUpperCase(),
                style: textTheme.labelMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),

        const SizedBox(height: 20),

        // Rule name
        Text(
          alert.ruleName,
          style: textTheme.headlineSmall?.copyWith(
            color: colorScheme.onSurface,
            fontWeight: FontWeight.w700,
          ),
        ),

        const SizedBox(height: 8),

        // Time
        Text(
          'Created ${_formatDate(alert.createdAt)}',
          style: textTheme.bodySmall?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),

        const SizedBox(height: 20),

        // Details card
        _SectionCard(
          title: 'Details',
          child: Column(
            children: [
              _Row(label: 'Agent ID', value: alert.agentId, mono: true),
              _Row(label: 'Rule', value: alert.ruleName),
              _Row(label: 'Severity', value: alert.severity.toUpperCase()),
              _Row(
                  label: 'Status',
                  value: alert.status.toUpperCase(),
                  isLast: true),
            ],
          ),
        ),

        const SizedBox(height: 16),

        // Description
        if (alert.description != null && alert.description!.isNotEmpty) ...[
          _SectionCard(
            title: 'Description',
            child: Padding(
              padding: const EdgeInsets.all(4),
              child: Text(
                alert.description!,
                style: textTheme.bodyMedium?.copyWith(
                  color: colorScheme.onSurface,
                  height: 1.6,
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // MITRE tactics
        if (alert.mitreTactics.isNotEmpty) ...[
          _SectionCard(
            title: 'MITRE Tactics',
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: alert.mitreTactics.map((tactic) {
                return Chip(
                  label: Text(tactic),
                  backgroundColor:
                      colorScheme.tertiaryContainer.withOpacity(0.7),
                  labelStyle: TextStyle(
                    color: colorScheme.onTertiaryContainer,
                    fontSize: 12,
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // MITRE techniques
        if (alert.mitreTechniques.isNotEmpty) ...[
          _SectionCard(
            title: 'MITRE Techniques',
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: alert.mitreTechniques.map((tech) {
                return Chip(
                  label: Text(tech),
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

        // Action buttons
        if (alert.status.toLowerCase() != 'resolved') ...[
          const SizedBox(height: 8),
          Text(
            'Actions',
            style: textTheme.titleSmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              if (alert.status.toLowerCase() == 'open')
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () =>
                        _updateStatus(context, ref, alert, 'acknowledged'),
                    icon: const Icon(Icons.check_circle_outline),
                    label: const Text('Acknowledge'),
                  ),
                ),
              if (alert.status.toLowerCase() == 'open')
                const SizedBox(width: 12),
              Expanded(
                child: FilledButton.icon(
                  onPressed: () =>
                      _updateStatus(context, ref, alert, 'resolved'),
                  icon: const Icon(Icons.done_all),
                  label: const Text('Resolve'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
        ],
      ],
    );
  }

  Future<void> _updateStatus(
    BuildContext context,
    WidgetRef ref,
    Alert alert,
    String newStatus,
  ) async {
    try {
      await ref.read(alertsProvider.notifier).updateStatus(alert.id, newStatus);
      ref.invalidate(alertDetailProvider(alert.id));
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content:
                Text('Alert ${newStatus == 'resolved' ? 'resolved' : 'acknowledged'}.'),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } on Exception catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
                'Failed: ${e.toString().replaceFirst('Exception: ', '')}'),
            backgroundColor: Theme.of(context).colorScheme.error,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    }
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
            Text('Failed to load alert',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error,
                textAlign: TextAlign.center,
                style: TextStyle(color: colorScheme.onSurfaceVariant)),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: () => ref.invalidate(alertDetailProvider(alertId)),
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
          Divider(height: 1, color: colorScheme.outlineVariant.withOpacity(0.3)),
      ],
    );
  }
}
