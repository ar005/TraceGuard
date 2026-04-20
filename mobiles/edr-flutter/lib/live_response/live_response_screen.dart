import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/live_response/live_response_provider.dart';
import 'package:edr_flutter/models/models.dart';

class LiveResponseScreen extends ConsumerStatefulWidget {
  const LiveResponseScreen({super.key});

  @override
  ConsumerState<LiveResponseScreen> createState() =>
      _LiveResponseScreenState();
}

class _LiveResponseScreenState extends ConsumerState<LiveResponseScreen> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final FocusNode _inputFocus = FocusNode();
  int _historyIndex = -1;

  @override
  void initState() {
    super.initState();
    Future.microtask(() {
      ref.read(liveResponseProvider.notifier).loadAgents();
    });
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    _inputFocus.dispose();
    super.dispose();
  }

  void _sendCommand() {
    final text = _inputController.text;
    if (text.trim().isEmpty) return;
    ref.read(liveResponseProvider.notifier).sendCommand(text);
    _inputController.clear();
    _historyIndex = -1;
    _scrollToBottom();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  void _navigateHistory(bool up, List<String> history) {
    if (history.isEmpty) return;
    setState(() {
      if (up) {
        _historyIndex =
            (_historyIndex + 1).clamp(0, history.length - 1);
      } else {
        _historyIndex = (_historyIndex - 1).clamp(-1, history.length - 1);
      }
    });
    if (_historyIndex >= 0) {
      _inputController.text = history[_historyIndex];
      _inputController.selection = TextSelection.fromPosition(
        TextPosition(offset: _inputController.text.length),
      );
    } else {
      _inputController.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    final lrState = ref.watch(liveResponseProvider);
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    // Auto-scroll when output changes
    if (lrState.output.isNotEmpty) {
      _scrollToBottom();
    }

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117), // Deep dark terminal bg
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        foregroundColor: const Color(0xFFE6EDF3),
        title: const Text('Live Response'),
        centerTitle: false,
        actions: [
          if (lrState.output.isNotEmpty)
            TextButton(
              onPressed: () =>
                  ref.read(liveResponseProvider.notifier).clearOutput(),
              child: const Text('Clear',
                  style: TextStyle(color: Color(0xFF8B949E))),
            ),
        ],
      ),
      body: Column(
        children: [
          // Agent selector
          _AgentSelector(lrState: lrState),

          // Terminal output
          Expanded(
            child: _TerminalOutput(
              lines: lrState.output,
              scrollController: _scrollController,
              isSending: lrState.isSending,
            ),
          ),

          // Input bar
          _InputBar(
            controller: _inputController,
            focusNode: _inputFocus,
            isSending: lrState.isSending,
            isConnected: lrState.isConnected,
            onSubmit: _sendCommand,
            onHistoryUp: () =>
                _navigateHistory(true, lrState.commandHistory),
            onHistoryDown: () =>
                _navigateHistory(false, lrState.commandHistory),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Agent selector
// ---------------------------------------------------------------------------

class _AgentSelector extends ConsumerWidget {
  final LiveResponseState lrState;

  const _AgentSelector({required this.lrState});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final notifier = ref.read(liveResponseProvider.notifier);

    return Container(
      color: const Color(0xFF161B22),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          Icon(Icons.computer_outlined,
              size: 18, color: const Color(0xFF8B949E)),
          const SizedBox(width: 10),
          Expanded(
            child: lrState.agentsLoading
                ? const Row(
                    children: [
                      SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Color(0xFF58A6FF),
                        ),
                      ),
                      SizedBox(width: 10),
                      Text(
                        'Loading agents…',
                        style: TextStyle(color: Color(0xFF8B949E), fontSize: 13),
                      ),
                    ],
                  )
                : DropdownButton<String>(
                    value: lrState.selectedAgentId,
                    hint: const Text(
                      'Select an agent',
                      style: TextStyle(
                          color: Color(0xFF8B949E), fontSize: 13),
                    ),
                    isExpanded: true,
                    dropdownColor: const Color(0xFF21262D),
                    underline: const SizedBox.shrink(),
                    style: const TextStyle(
                        color: Color(0xFFE6EDF3), fontSize: 13),
                    onChanged: (id) => notifier.selectAgent(id),
                    items: [
                      const DropdownMenuItem<String>(
                        value: null,
                        child: Text(
                          '— No agent —',
                          style: TextStyle(
                              color: Color(0xFF8B949E), fontSize: 13),
                        ),
                      ),
                      ...lrState.agents.map((agent) {
                        return DropdownMenuItem<String>(
                          value: agent.agentId,
                          child: Row(
                            children: [
                              Container(
                                width: 8,
                                height: 8,
                                decoration: BoxDecoration(
                                  color: agent.isOnline
                                      ? const Color(0xFF3FB950)
                                      : const Color(0xFF8B949E),
                                  shape: BoxShape.circle,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Text(
                                agent.hostname,
                                style: const TextStyle(
                                    color: Color(0xFFE6EDF3), fontSize: 13),
                              ),
                              const SizedBox(width: 6),
                              Text(
                                '(${agent.os})',
                                style: const TextStyle(
                                  color: Color(0xFF8B949E),
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                        );
                      }),
                    ],
                  ),
          ),
          if (lrState.agentsError != null)
            Tooltip(
              message: lrState.agentsError!,
              child: const Icon(Icons.warning_amber_outlined,
                  size: 18, color: Color(0xFFD29922)),
            ),
          IconButton(
            icon: const Icon(Icons.refresh_outlined,
                size: 18, color: Color(0xFF8B949E)),
            tooltip: 'Refresh agents',
            onPressed: () => notifier.loadAgents(),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Terminal output
// ---------------------------------------------------------------------------

class _TerminalOutput extends StatelessWidget {
  final List<OutputLine> lines;
  final ScrollController scrollController;
  final bool isSending;

  const _TerminalOutput({
    required this.lines,
    required this.scrollController,
    required this.isSending,
  });

  @override
  Widget build(BuildContext context) {
    if (lines.isEmpty) {
      return const Center(
        child: Text(
          'Select an agent to start a live response session.',
          style: TextStyle(
            color: Color(0xFF8B949E),
            fontSize: 13,
          ),
          textAlign: TextAlign.center,
        ),
      );
    }

    return ListView.builder(
      controller: scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      itemCount: lines.length + (isSending ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == lines.length) {
          // Sending indicator
          return const Padding(
            padding: EdgeInsets.symmetric(vertical: 4),
            child: Row(
              children: [
                SizedBox(
                  width: 12,
                  height: 12,
                  child: CircularProgressIndicator(
                    strokeWidth: 1.5,
                    color: Color(0xFF58A6FF),
                  ),
                ),
                SizedBox(width: 8),
                Text(
                  'Executing…',
                  style: TextStyle(
                    color: Color(0xFF8B949E),
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          );
        }

        final line = lines[index];
        return _OutputLineWidget(line: line);
      },
    );
  }
}

class _OutputLineWidget extends StatelessWidget {
  final OutputLine line;

  const _OutputLineWidget({required this.line});

  Color _colorForType(OutputLineType type) {
    switch (type) {
      case OutputLineType.prompt:
        return const Color(0xFF3FB950); // green
      case OutputLineType.output:
        return const Color(0xFFE6EDF3); // white
      case OutputLineType.error:
        return const Color(0xFFF85149); // red
      case OutputLineType.system:
        return const Color(0xFF8B949E); // grey
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: SelectableText(
        line.text,
        style: TextStyle(
          fontFamily: 'monospace',
          fontSize: 13,
          height: 1.5,
          color: _colorForType(line.type),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Input bar
// ---------------------------------------------------------------------------

class _InputBar extends StatelessWidget {
  final TextEditingController controller;
  final FocusNode focusNode;
  final bool isSending;
  final bool isConnected;
  final VoidCallback onSubmit;
  final VoidCallback onHistoryUp;
  final VoidCallback onHistoryDown;

  const _InputBar({
    required this.controller,
    required this.focusNode,
    required this.isSending,
    required this.isConnected,
    required this.onSubmit,
    required this.onHistoryUp,
    required this.onHistoryDown,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      color: const Color(0xFF161B22),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      child: Row(
        children: [
          const Text(
            '\$',
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 16,
              color: Color(0xFF3FB950),
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: KeyboardListener(
              focusNode: FocusNode(),
              onKeyEvent: (event) {
                if (event is KeyDownEvent) {
                  if (event.logicalKey == LogicalKeyboardKey.arrowUp) {
                    onHistoryUp();
                  } else if (event.logicalKey == LogicalKeyboardKey.arrowDown) {
                    onHistoryDown();
                  }
                }
              },
              child: TextField(
                controller: controller,
                focusNode: focusNode,
                enabled: isConnected && !isSending,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 14,
                  color: Color(0xFFE6EDF3),
                ),
                decoration: InputDecoration(
                  hintText: isConnected
                      ? 'Enter command…'
                      : 'Select an agent first',
                  hintStyle: const TextStyle(
                    color: Color(0xFF8B949E),
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                  border: InputBorder.none,
                  isDense: true,
                  contentPadding: const EdgeInsets.symmetric(vertical: 8),
                ),
                onSubmitted: (_) => onSubmit(),
                textInputAction: TextInputAction.send,
              ),
            ),
          ),
          const SizedBox(width: 8),
          isSending
              ? const SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Color(0xFF58A6FF),
                  ),
                )
              : IconButton(
                  icon: const Icon(Icons.send_outlined,
                      size: 20, color: Color(0xFF58A6FF)),
                  onPressed: isConnected ? onSubmit : null,
                  tooltip: 'Send command',
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
        ],
      ),
    );
  }
}
