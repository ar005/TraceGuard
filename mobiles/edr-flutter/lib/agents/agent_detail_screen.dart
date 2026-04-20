import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:edr_flutter/agents/agents_provider.dart';
import 'package:edr_flutter/alerts/alerts_screen.dart';
import 'package:edr_flutter/events/events_screen.dart';
import 'package:edr_flutter/models/models.dart';

class AgentDetailScreen extends ConsumerStatefulWidget {
  final String agentId;

  const AgentDetailScreen({super.key, required this.agentId});

  @override
  ConsumerState<AgentDetailScreen> createState() => _AgentDetailScreenState();
}

class _AgentDetailScreenState extends ConsumerState<AgentDetailScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final agentAsync = ref.watch(agentDetailProvider(widget.agentId));
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: agentAsync.when(
          data: (agent) => Text(agent.hostname),
          loading: () => const Text('Loading…'),
          error: (_, __) => const Text('Agent'),
        ),
        leading: BackButton(onPressed: () => context.go('/agents')),
        bottom: TabBar(
          controller: _tabController,
          isScrollable: false,
          tabs: const [
            Tab(text: 'Overview'),
            Tab(text: 'Events'),
            Tab(text: 'Alerts'),
            Tab(text: 'Packages'),
          ],
        ),
      ),
      body: agentAsync.when(
        data: (agent) => TabBarView(
          controller: _tabController,
          children: [
            _OverviewTab(agent: agent),
            EventsScreen(agentIdFilter: widget.agentId),
            AlertsScreen(agentIdFilter: widget.agentId),
            _PackagesTab(agent: agent),
          ],
        ),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => _buildError(context, err.toString()),
      ),
    );
  }

  Widget _buildError(BuildContext context, String error) {
    final colorScheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline, size: 48, color: colorScheme.error),
            const SizedBox(height: 16),
            Text('Failed to load agent', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error, textAlign: TextAlign.center,
                style: TextStyle(color: colorScheme.onSurfaceVariant)),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: () => ref.invalidate(agentDetailProvider(widget.agentId)),
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
// Overview tab
// ---------------------------------------------------------------------------

class _OverviewTab extends StatelessWidget {
  final Agent agent;

  const _OverviewTab({required this.agent});

  String _timeAgo(DateTime? dt) {
    if (dt == null) return 'Never';
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
    final isOnline = agent.isOnline;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Status banner
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            color: isOnline
                ? const Color(0xFF4CAF50).withOpacity(0.12)
                : colorScheme.onSurfaceVariant.withOpacity(0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: isOnline
                  ? const Color(0xFF4CAF50).withOpacity(0.3)
                  : colorScheme.outlineVariant.withOpacity(0.4),
            ),
          ),
          child: Row(
            children: [
              Icon(
                isOnline ? Icons.circle : Icons.circle_outlined,
                size: 14,
                color: isOnline
                    ? const Color(0xFF4CAF50)
                    : colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 8),
              Text(
                isOnline ? 'Online' : 'Offline',
                style: textTheme.bodyMedium?.copyWith(
                  color: isOnline
                      ? const Color(0xFF4CAF50)
                      : colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Details card
        Card(
          elevation: 0,
          color: colorScheme.surfaceContainerHigh,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
            side: BorderSide(
                color: colorScheme.outlineVariant.withOpacity(0.4)),
          ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Agent Details',
                  style: textTheme.titleSmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.5,
                  ),
                ),
                const SizedBox(height: 16),
                _DetailRow(label: 'Hostname', value: agent.hostname),
                _DetailRow(label: 'Operating System', value: agent.os),
                _DetailRow(label: 'IP Address', value: agent.ip, mono: true),
                _DetailRow(label: 'Agent Version', value: agent.agentVer),
                _DetailRow(label: 'Agent ID', value: agent.id, mono: true),
                _DetailRow(
                  label: 'Last Seen',
                  value: agent.lastSeen != null
                      ? '${_timeAgo(agent.lastSeen)} · ${agent.lastSeen!.toLocal().toString().substring(0, 19)}'
                      : 'Never',
                  isLast: true,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;
  final bool mono;
  final bool isLast;

  const _DetailRow({
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
          padding: const EdgeInsets.symmetric(vertical: 10),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 130,
                child: Text(
                  label,
                  style: textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
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

// ---------------------------------------------------------------------------
// Packages tab (placeholder)
// ---------------------------------------------------------------------------

class _PackagesTab extends StatelessWidget {
  final Agent agent;

  const _PackagesTab({required this.agent});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    String osFamily = agent.os.toLowerCase();
    String message;
    if (osFamily.contains('windows')) {
      message = 'Package inventory not yet available for Windows.';
    } else if (osFamily.contains('linux')) {
      message = 'Package inventory not yet available for Linux.';
    } else {
      message = 'Package inventory not yet available for this OS.';
    }

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.inventory_2_outlined,
              size: 64,
              color: colorScheme.onSurfaceVariant.withOpacity(0.5),
            ),
            const SizedBox(height: 16),
            Text(
              'Package Inventory',
              style: textTheme.titleMedium?.copyWith(
                color: colorScheme.onSurface,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              message,
              textAlign: TextAlign.center,
              style: textTheme.bodyMedium?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
