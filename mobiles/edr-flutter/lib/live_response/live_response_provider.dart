import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/auth/auth_provider.dart';
import 'package:edr_flutter/models/models.dart';

// ---------------------------------------------------------------------------
// Output line types
// ---------------------------------------------------------------------------

enum OutputLineType { prompt, output, error, system }

class OutputLine {
  final String text;
  final OutputLineType type;
  final DateTime timestamp;

  OutputLine({
    required this.text,
    required this.type,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();
}

// ---------------------------------------------------------------------------
// Live Response State
// ---------------------------------------------------------------------------

class LiveResponseState {
  final String? selectedAgentId;
  final List<LiveResponseAgent> agents;
  final bool agentsLoading;
  final String? agentsError;
  final List<OutputLine> output;
  final bool isSending;
  final String? sendError;
  final List<String> commandHistory;

  const LiveResponseState({
    this.selectedAgentId,
    this.agents = const [],
    this.agentsLoading = false,
    this.agentsError,
    this.output = const [],
    this.isSending = false,
    this.sendError,
    this.commandHistory = const [],
  });

  bool get isConnected => selectedAgentId != null;

  LiveResponseState copyWith({
    String? selectedAgentId,
    List<LiveResponseAgent>? agents,
    bool? agentsLoading,
    String? agentsError,
    List<OutputLine>? output,
    bool? isSending,
    String? sendError,
    List<String>? commandHistory,
    bool clearAgentsError = false,
    bool clearSendError = false,
    bool clearAgent = false,
  }) {
    return LiveResponseState(
      selectedAgentId:
          clearAgent ? null : (selectedAgentId ?? this.selectedAgentId),
      agents: agents ?? this.agents,
      agentsLoading: agentsLoading ?? this.agentsLoading,
      agentsError:
          clearAgentsError ? null : (agentsError ?? this.agentsError),
      output: output ?? this.output,
      isSending: isSending ?? this.isSending,
      sendError: clearSendError ? null : (sendError ?? this.sendError),
      commandHistory: commandHistory ?? this.commandHistory,
    );
  }
}

// ---------------------------------------------------------------------------
// Live Response Notifier
// ---------------------------------------------------------------------------

class LiveResponseNotifier extends StateNotifier<LiveResponseState> {
  final Ref _ref;

  LiveResponseNotifier(this._ref) : super(const LiveResponseState());

  // ---------------------------------------------------------------------------
  // Agents
  // ---------------------------------------------------------------------------

  Future<void> loadAgents() async {
    state = state.copyWith(agentsLoading: true, clearAgentsError: true);
    try {
      final api = _ref.read(edrApiProvider);
      final agents = await api.getLiveResponseAgents();
      state = state.copyWith(agents: agents, agentsLoading: false);
    } on Exception catch (e) {
      state = state.copyWith(
        agentsLoading: false,
        agentsError: e.toString().replaceFirst('Exception: ', ''),
      );
    }
  }

  void selectAgent(String? agentId) {
    if (agentId == state.selectedAgentId) return;
    state = state.copyWith(
      selectedAgentId: agentId,
      output: agentId != null
          ? [
              OutputLine(
                text: 'Connected to agent $agentId',
                type: OutputLineType.system,
              ),
              OutputLine(
                text: 'Type a command and press Enter to execute.',
                type: OutputLineType.system,
              ),
            ]
          : [],
      clearAgent: agentId == null,
    );
  }

  // ---------------------------------------------------------------------------
  // Commands
  // ---------------------------------------------------------------------------

  Future<void> sendCommand(String rawInput) async {
    final trimmed = rawInput.trim();
    if (trimmed.isEmpty) return;
    if (state.selectedAgentId == null) return;

    // Parse command + args
    final parts = trimmed.split(RegExp(r'\s+'));
    final command = parts.first;
    final args = parts.length > 1 ? parts.sublist(1) : <String>[];

    // Add prompt line
    final newOutput = List<OutputLine>.from(state.output)
      ..add(OutputLine(
        text: '${_promptPrefix()} $trimmed',
        type: OutputLineType.prompt,
      ));

    // Save to history (deduplicated, newest first)
    final history = [
      trimmed,
      ...state.commandHistory.where((c) => c != trimmed),
    ];
    if (history.length > 50) history.removeRange(50, history.length);

    state = state.copyWith(
      output: newOutput,
      commandHistory: history,
      isSending: true,
      clearSendError: true,
    );

    try {
      final api = _ref.read(edrApiProvider);
      final result = await api.sendLiveResponseCommand(
        agentId: state.selectedAgentId!,
        command: command,
        args: args,
      );

      final outputText = result['output']?.toString() ??
          result['stdout']?.toString() ??
          result['result']?.toString() ??
          '';

      final errorText = result['error']?.toString() ??
          result['stderr']?.toString() ??
          '';

      final updated = List<OutputLine>.from(state.output);
      if (outputText.isNotEmpty) {
        // Split multi-line output
        for (final line in outputText.split('\n')) {
          updated.add(OutputLine(text: line, type: OutputLineType.output));
        }
      }
      if (errorText.isNotEmpty) {
        for (final line in errorText.split('\n')) {
          if (line.isNotEmpty) {
            updated.add(OutputLine(text: line, type: OutputLineType.error));
          }
        }
      }
      if (outputText.isEmpty && errorText.isEmpty) {
        updated.add(OutputLine(
          text: '(no output)',
          type: OutputLineType.output,
        ));
      }

      state = state.copyWith(output: updated, isSending: false);
    } on Exception catch (e) {
      final errorMsg = e.toString().replaceFirst('Exception: ', '');
      final updated = List<OutputLine>.from(state.output)
        ..add(OutputLine(text: 'Error: $errorMsg', type: OutputLineType.error));
      state = state.copyWith(
        output: updated,
        isSending: false,
        sendError: errorMsg,
      );
    }
  }

  String _promptPrefix() {
    final agentId = state.selectedAgentId ?? '';
    final short = agentId.length > 8 ? agentId.substring(0, 8) : agentId;
    return 'agent@$short \$';
  }

  void clearOutput() {
    state = state.copyWith(output: []);
  }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

final liveResponseProvider =
    StateNotifierProvider<LiveResponseNotifier, LiveResponseState>((ref) {
  return LiveResponseNotifier(ref);
});
