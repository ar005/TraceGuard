import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/events/events_provider.dart';
import 'package:edr_flutter/models/models.dart';

// Known event types for filter chips
const _kEventTypes = [
  'process',
  'network',
  'file',
  'dns',
  'auth',
  'module',
  'syscall',
  'alert',
];

class EventsScreen extends ConsumerStatefulWidget {
  /// When provided, shows historical events for this agent (no live stream).
  final String? agentIdFilter;

  const EventsScreen({super.key, this.agentIdFilter});

  @override
  ConsumerState<EventsScreen> createState() => _EventsScreenState();
}

class _EventsScreenState extends ConsumerState<EventsScreen> {
  final ScrollController _scrollController = ScrollController();
  bool _autoScroll = true;

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

    // If embedded in AgentDetail, load historical events
    if (widget.agentIdFilter != null) {
      Future.microtask(() {
        ref.read(eventsProvider.notifier).loadHistorical(
              agentId: widget.agentIdFilter,
            );
      });
    } else {
      // Connect to SSE stream
      Future.microtask(() {
        ref.read(eventsProvider.notifier).connect();
      });
    }
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    final atBottom = _scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 50;
    if (_autoScroll != atBottom) {
      setState(() => _autoScroll = atBottom);
    }
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final eventsState = ref.watch(eventsProvider);
    final colorScheme = Theme.of(context).colorScheme;
    final isEmbedded = widget.agentIdFilter != null;

    // Auto-scroll when new events arrive (if not paused and at bottom)
    if (_autoScroll && !eventsState.isPaused && eventsState.events.isNotEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_scrollController.hasClients) {
          _scrollToBottom();
        }
      });
    }

    Widget body = Column(
      children: [
        _buildHeader(context, eventsState, isEmbedded),
        if (eventsState.error != null)
          _ErrorBanner(message: eventsState.error!),
        Expanded(
          child: eventsState.events.isEmpty
              ? _buildEmpty(context, eventsState)
              : _buildEventList(context, eventsState),
        ),
      ],
    );

    if (isEmbedded) return body;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Events'),
        centerTitle: false,
      ),
      body: body,
      floatingActionButton: !_autoScroll
          ? FloatingActionButton.small(
              onPressed: () {
                setState(() => _autoScroll = true);
                _scrollToBottom();
              },
              tooltip: 'Jump to latest',
              child: const Icon(Icons.arrow_downward),
            )
          : null,
    );
  }

  Widget _buildHeader(
    BuildContext context,
    EventsState state,
    bool isEmbedded,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    final notifier = ref.read(eventsProvider.notifier);

    return Container(
      color: colorScheme.surface,
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Status + control row
          Row(
            children: [
              // Connection indicator
              if (!isEmbedded) ...[
                Icon(
                  state.isConnected ? Icons.circle : Icons.circle_outlined,
                  size: 10,
                  color: state.isConnected
                      ? const Color(0xFF4CAF50)
                      : colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 6),
                Text(
                  state.isConnected ? 'Live' : 'Disconnected',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: state.isConnected
                            ? const Color(0xFF4CAF50)
                            : colorScheme.onSurfaceVariant,
                      ),
                ),
                const SizedBox(width: 12),
              ],

              // Event count
              Text(
                '${state.events.length} event${state.events.length != 1 ? 's' : ''}',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                    ),
              ),

              const Spacer(),

              // Clear button
              if (state.events.isNotEmpty)
                TextButton(
                  onPressed: notifier.clearEvents,
                  child: const Text('Clear'),
                ),

              // Pause / resume (live stream only)
              if (!isEmbedded)
                IconButton(
                  icon: Icon(
                    state.isPaused
                        ? Icons.play_arrow_outlined
                        : Icons.pause_outlined,
                  ),
                  tooltip: state.isPaused ? 'Resume' : 'Pause',
                  onPressed: notifier.togglePause,
                ),

              // Reconnect (if disconnected)
              if (!isEmbedded && !state.isConnected)
                IconButton(
                  icon: const Icon(Icons.refresh_outlined),
                  tooltip: 'Reconnect',
                  onPressed: notifier.connect,
                ),

              // Reload (embedded)
              if (isEmbedded)
                IconButton(
                  icon: const Icon(Icons.refresh_outlined),
                  tooltip: 'Reload',
                  onPressed: () => notifier.loadHistorical(
                    agentId: widget.agentIdFilter,
                  ),
                ),
            ],
          ),

          // Event type filter chips
          if (!isEmbedded)
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  children: [
                    _EventTypeChip(
                      label: 'ALL',
                      selected: state.eventTypeFilter == null,
                      onSelected: (_) => notifier.setEventTypeFilter(null),
                    ),
                    ..._kEventTypes.map((type) => _EventTypeChip(
                          label: type.toUpperCase(),
                          selected: state.eventTypeFilter == type,
                          onSelected: (_) =>
                              notifier.setEventTypeFilter(type),
                          color: _eventTypeColor(type),
                        )),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildEventList(BuildContext context, EventsState state) {
    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      itemCount: state.events.length,
      itemBuilder: (context, index) {
        final event = state.events[index];
        return _EventTile(event: event);
      },
    );
  }

  Widget _buildEmpty(BuildContext context, EventsState state) {
    final colorScheme = Theme.of(context).colorScheme;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.stream_outlined,
            size: 64,
            color: colorScheme.onSurfaceVariant.withOpacity(0.5),
          ),
          const SizedBox(height: 16),
          Text(
            state.isConnected ? 'Waiting for events…' : 'No events',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
          ),
          if (!state.isConnected && widget.agentIdFilter == null) ...[
            const SizedBox(height: 8),
            Text(
              'Tap the refresh button to reconnect.',
              style: TextStyle(color: colorScheme.onSurfaceVariant),
            ),
          ],
        ],
      ),
    );
  }

  Color _eventTypeColor(String type) {
    switch (type.toLowerCase()) {
      case 'process':
        return const Color(0xFF7C4DFF);
      case 'network':
        return const Color(0xFF0288D1);
      case 'file':
        return const Color(0xFF00796B);
      case 'dns':
        return const Color(0xFF0097A7);
      case 'auth':
        return const Color(0xFFE64A19);
      case 'module':
        return const Color(0xFF558B2F);
      case 'syscall':
        return const Color(0xFF6D4C41);
      case 'alert':
        return const Color(0xFFF44336);
      default:
        return const Color(0xFF757575);
    }
  }
}

// ---------------------------------------------------------------------------
// Event type filter chip
// ---------------------------------------------------------------------------

class _EventTypeChip extends StatelessWidget {
  final String label;
  final bool selected;
  final ValueChanged<bool> onSelected;
  final Color? color;

  const _EventTypeChip({
    required this.label,
    required this.selected,
    required this.onSelected,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final chipColor = color ?? Theme.of(context).colorScheme.primary;
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: FilterChip(
        label: Text(label, style: const TextStyle(fontSize: 11)),
        selected: selected,
        selectedColor: chipColor.withOpacity(0.18),
        checkmarkColor: chipColor,
        labelStyle: TextStyle(
          color: selected
              ? chipColor
              : Theme.of(context).colorScheme.onSurfaceVariant,
          fontWeight: selected ? FontWeight.w600 : FontWeight.normal,
        ),
        onSelected: onSelected,
        padding: const EdgeInsets.symmetric(horizontal: 2),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Event tile
// ---------------------------------------------------------------------------

class _EventTile extends StatelessWidget {
  final EventRecord event;

  const _EventTile({required this.event});

  Color _eventTypeColor(String type) {
    switch (type.toLowerCase()) {
      case 'process':
        return const Color(0xFF7C4DFF);
      case 'network':
        return const Color(0xFF0288D1);
      case 'file':
        return const Color(0xFF00796B);
      case 'dns':
        return const Color(0xFF0097A7);
      case 'auth':
        return const Color(0xFFE64A19);
      case 'module':
        return const Color(0xFF558B2F);
      case 'syscall':
        return const Color(0xFF6D4C41);
      case 'alert':
        return const Color(0xFFF44336);
      default:
        return const Color(0xFF757575);
    }
  }

  String _formatTime(DateTime dt) {
    final local = dt.toLocal();
    return '${local.hour.toString().padLeft(2, '0')}:'
        '${local.minute.toString().padLeft(2, '0')}:'
        '${local.second.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    final typeColor = _eventTypeColor(event.eventType);

    return Card(
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 2),
      color: colorScheme.surfaceContainerHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: BorderSide(color: colorScheme.outlineVariant.withOpacity(0.25)),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Event type badge
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
              decoration: BoxDecoration(
                color: typeColor.withOpacity(0.12),
                borderRadius: BorderRadius.circular(5),
              ),
              child: Text(
                event.eventType.toUpperCase(),
                style: textTheme.labelSmall?.copyWith(
                  color: typeColor,
                  fontWeight: FontWeight.w700,
                  fontSize: 10,
                ),
              ),
            ),
            const SizedBox(width: 10),

            // Hostname + payload
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          event.hostname,
                          style: textTheme.bodySmall?.copyWith(
                            color: colorScheme.onSurface,
                            fontWeight: FontWeight.w600,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      Text(
                        _formatTime(event.timestamp),
                        style: textTheme.bodySmall?.copyWith(
                          color: colorScheme.onSurfaceVariant,
                          fontFamily: 'monospace',
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    event.payloadPreview,
                    style: textTheme.bodySmall?.copyWith(
                      color: colorScheme.onSurfaceVariant,
                      fontFamily: 'monospace',
                      fontSize: 11,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Error banner
// ---------------------------------------------------------------------------

class _ErrorBanner extends StatelessWidget {
  final String message;

  const _ErrorBanner({required this.message});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      color: colorScheme.errorContainer,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Text(
        message,
        style: TextStyle(
          color: colorScheme.onErrorContainer,
          fontSize: 12,
        ),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    );
  }
}
