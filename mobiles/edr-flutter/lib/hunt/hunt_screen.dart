import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:edr_flutter/hunt/hunt_provider.dart';
import 'package:edr_flutter/models/models.dart';

class HuntScreen extends ConsumerStatefulWidget {
  const HuntScreen({super.key});

  @override
  ConsumerState<HuntScreen> createState() => _HuntScreenState();
}

class _HuntScreenState extends ConsumerState<HuntScreen> {
  final _queryController = TextEditingController();
  final _focusNode = FocusNode();

  @override
  void dispose() {
    _queryController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _runQuery() {
    final query = _queryController.text.trim();
    if (query.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter a query.'),
          behavior: SnackBarBehavior.floating,
        ),
      );
      return;
    }
    ref.read(huntProvider.notifier).runQuery(query);
  }

  void _applyTemplate(QueryTemplate template) {
    _queryController.text = template.query;
    _queryController.selection = TextSelection.fromPosition(
      TextPosition(offset: template.query.length),
    );
    Navigator.pop(context);
    _focusNode.requestFocus();
  }

  void _showTemplates() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => _TemplatesSheet(onApply: _applyTemplate),
    );
  }

  @override
  Widget build(BuildContext context) {
    final huntState = ref.watch(huntProvider);
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Threat Hunt'),
        centerTitle: false,
        actions: [
          if (huntState.result != null)
            TextButton(
              onPressed: () {
                ref.read(huntProvider.notifier).clearResults();
                _queryController.clear();
              },
              child: const Text('Clear'),
            ),
        ],
      ),
      body: Column(
        children: [
          // Query input area
          Container(
            color: colorScheme.surfaceContainerHigh,
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextFormField(
                  controller: _queryController,
                  focusNode: _focusNode,
                  maxLines: 5,
                  minLines: 3,
                  style: textTheme.bodyMedium?.copyWith(
                    fontFamily: 'monospace',
                    color: colorScheme.onSurface,
                  ),
                  decoration: InputDecoration(
                    hintText:
                        'SELECT * FROM events WHERE event_type = \'process\' LIMIT 100',
                    hintStyle: TextStyle(
                      color: colorScheme.onSurfaceVariant.withOpacity(0.5),
                      fontFamily: 'monospace',
                      fontSize: 13,
                    ),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                    filled: true,
                    fillColor: colorScheme.surface,
                    contentPadding: const EdgeInsets.all(14),
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    OutlinedButton.icon(
                      onPressed: _showTemplates,
                      icon: const Icon(Icons.list_alt_outlined, size: 18),
                      label: const Text('Templates'),
                    ),
                    const Spacer(),
                    FilledButton.icon(
                      onPressed: huntState.isLoading ? null : _runQuery,
                      icon: huntState.isLoading
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child:
                                  CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.search, size: 18),
                      label: const Text('Run Query'),
                    ),
                  ],
                ),
              ],
            ),
          ),

          // Error
          if (huntState.error != null)
            Container(
              width: double.infinity,
              color: colorScheme.errorContainer,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: Row(
                children: [
                  Icon(Icons.error_outline,
                      size: 16, color: colorScheme.onErrorContainer),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      huntState.error!,
                      style: TextStyle(
                        color: colorScheme.onErrorContainer,
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),

          // Results
          Expanded(
            child: huntState.result == null
                ? _buildIdle(context)
                : _buildResults(context, huntState.result!),
          ),
        ],
      ),
    );
  }

  Widget _buildIdle(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.manage_search_outlined,
            size: 64,
            color: colorScheme.onSurfaceVariant.withOpacity(0.4),
          ),
          const SizedBox(height: 16),
          Text(
            'Enter a query to hunt for threats',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
          ),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: _showTemplates,
            icon: const Icon(Icons.list_alt_outlined),
            label: const Text('Browse templates'),
          ),
        ],
      ),
    );
  }

  Widget _buildResults(BuildContext context, HuntResult result) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    if (result.rows.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.inbox_outlined,
                size: 48, color: colorScheme.onSurfaceVariant),
            const SizedBox(height: 16),
            Text('No results', style: textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(
              'The query returned 0 rows.',
              style: TextStyle(color: colorScheme.onSurfaceVariant),
            ),
          ],
        ),
      );
    }

    final columns = result.rows.first.keys.toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Text(
            '${result.total} row${result.total != 1 ? 's' : ''}',
            style: textTheme.bodySmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
          ),
        ),
        Expanded(
          child: Scrollbar(
            thumbVisibility: true,
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: SingleChildScrollView(
                scrollDirection: Axis.vertical,
                padding: const EdgeInsets.only(left: 16, right: 16, bottom: 16),
                child: DataTable(
                  headingRowColor: WidgetStateProperty.all(
                    colorScheme.surfaceContainerHigh,
                  ),
                  border: TableBorder.all(
                    color: colorScheme.outlineVariant.withOpacity(0.3),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  columnSpacing: 24,
                  headingRowHeight: 40,
                  dataRowMinHeight: 36,
                  dataRowMaxHeight: 52,
                  columns: columns
                      .map(
                        (col) => DataColumn(
                          label: Text(
                            col,
                            style: textTheme.labelSmall?.copyWith(
                              fontWeight: FontWeight.w700,
                              color: colorScheme.onSurface,
                            ),
                          ),
                        ),
                      )
                      .toList(),
                  rows: result.rows.map((row) {
                    return DataRow(
                      cells: columns.map((col) {
                        final value = row[col];
                        return DataCell(
                          ConstrainedBox(
                            constraints:
                                const BoxConstraints(maxWidth: 300),
                            child: Text(
                              value?.toString() ?? '',
                              style: textTheme.bodySmall?.copyWith(
                                fontFamily: 'monospace',
                                color: colorScheme.onSurface,
                              ),
                              overflow: TextOverflow.ellipsis,
                              maxLines: 2,
                            ),
                          ),
                        );
                      }).toList(),
                    );
                  }).toList(),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Templates bottom sheet
// ---------------------------------------------------------------------------

class _TemplatesSheet extends StatelessWidget {
  final ValueChanged<QueryTemplate> onApply;

  const _TemplatesSheet({required this.onApply});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return DraggableScrollableSheet(
      initialChildSize: 0.6,
      minChildSize: 0.4,
      maxChildSize: 0.9,
      expand: false,
      builder: (context, scrollController) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Handle
            Center(
              child: Container(
                margin: const EdgeInsets.only(top: 12, bottom: 8),
                width: 36,
                height: 4,
                decoration: BoxDecoration(
                  color: colorScheme.outlineVariant,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),

            Padding(
              padding:
                  const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
              child: Text(
                'Query Templates',
                style: textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),

            const Divider(height: 1),

            Expanded(
              child: ListView.separated(
                controller: scrollController,
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: kQueryTemplates.length,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final template = kQueryTemplates[index];
                  return ListTile(
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
                    leading: Container(
                      width: 40,
                      height: 40,
                      decoration: BoxDecoration(
                        color:
                            colorScheme.primaryContainer.withOpacity(0.7),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(
                        Icons.code_outlined,
                        size: 20,
                        color: colorScheme.primary,
                      ),
                    ),
                    title: Text(
                      template.name,
                      style: textTheme.bodyMedium?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    subtitle: Text(
                      template.description,
                      style: textTheme.bodySmall?.copyWith(
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                    onTap: () => onApply(template),
                  );
                },
              ),
            ),
          ],
        );
      },
    );
  }
}
