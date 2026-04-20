import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:edr_flutter/auth/auth_provider.dart';

// ---------------------------------------------------------------------------
// Settings state / provider
// ---------------------------------------------------------------------------

class SettingsState {
  final String backendUrl;
  final String apiToken;
  final ThemeMode themeMode;
  final bool isSaving;

  const SettingsState({
    this.backendUrl = 'http://localhost:8080',
    this.apiToken = '',
    this.themeMode = ThemeMode.dark,
    this.isSaving = false,
  });

  SettingsState copyWith({
    String? backendUrl,
    String? apiToken,
    ThemeMode? themeMode,
    bool? isSaving,
  }) {
    return SettingsState(
      backendUrl: backendUrl ?? this.backendUrl,
      apiToken: apiToken ?? this.apiToken,
      themeMode: themeMode ?? this.themeMode,
      isSaving: isSaving ?? this.isSaving,
    );
  }
}

const _kBackendUrlKey = 'edr_backend_url';
const _kApiTokenKey = 'edr_api_token_override';
const _kThemeModeKey = 'edr_theme_mode';

class SettingsNotifier extends StateNotifier<SettingsState> {
  SettingsNotifier() : super(const SettingsState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final url =
        prefs.getString(_kBackendUrlKey) ?? 'http://localhost:8080';
    final token = prefs.getString(_kApiTokenKey) ?? '';
    final themeModeStr = prefs.getString(_kThemeModeKey) ?? 'dark';
    final themeMode = _parseThemeMode(themeModeStr);
    state = state.copyWith(
      backendUrl: url,
      apiToken: token,
      themeMode: themeMode,
    );
  }

  Future<void> save({
    required String backendUrl,
    required String apiToken,
    required ThemeMode themeMode,
  }) async {
    state = state.copyWith(isSaving: true);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kBackendUrlKey, backendUrl.trim());
    await prefs.setString(_kApiTokenKey, apiToken.trim());
    await prefs.setString(_kThemeModeKey, _themeModeToString(themeMode));
    state = state.copyWith(
      backendUrl: backendUrl.trim(),
      apiToken: apiToken.trim(),
      themeMode: themeMode,
      isSaving: false,
    );
  }

  ThemeMode _parseThemeMode(String value) {
    switch (value) {
      case 'light':
        return ThemeMode.light;
      case 'system':
        return ThemeMode.system;
      default:
        return ThemeMode.dark;
    }
  }

  String _themeModeToString(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.light:
        return 'light';
      case ThemeMode.system:
        return 'system';
      default:
        return 'dark';
    }
  }
}

final settingsProvider =
    StateNotifierProvider<SettingsNotifier, SettingsState>(
  (_) => SettingsNotifier(),
);

// ---------------------------------------------------------------------------
// Settings Screen
// ---------------------------------------------------------------------------

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _urlController;
  late TextEditingController _tokenController;
  late ThemeMode _selectedTheme;
  bool _obscureToken = true;
  bool _hasLoaded = false;

  @override
  void initState() {
    super.initState();
    _urlController = TextEditingController();
    _tokenController = TextEditingController();
    _selectedTheme = ThemeMode.dark;
  }

  @override
  void dispose() {
    _urlController.dispose();
    _tokenController.dispose();
    super.dispose();
  }

  void _syncFromState(SettingsState settings) {
    if (!_hasLoaded) {
      _urlController.text = settings.backendUrl;
      _tokenController.text = settings.apiToken;
      _selectedTheme = settings.themeMode;
      _hasLoaded = true;
    }
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;
    await ref.read(settingsProvider.notifier).save(
          backendUrl: _urlController.text,
          apiToken: _tokenController.text,
          themeMode: _selectedTheme,
        );
    // Update backend URL provider so Dio picks it up
    ref.read(backendUrlProvider.notifier).state = _urlController.text.trim();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Settings saved.'),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(settingsProvider);
    final authState = ref.watch(authProvider);
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    _syncFromState(settings);

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: AppBar(
        title: const Text('Settings'),
        centerTitle: false,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Current user info
              _SectionHeader(title: 'Account'),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerHigh,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                  side: BorderSide(
                      color: colorScheme.outlineVariant.withOpacity(0.4)),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      _InfoRow(
                        icon: Icons.email_outlined,
                        label: 'Email',
                        value: authState.email ?? '—',
                      ),
                      const Divider(height: 16),
                      _InfoRow(
                        icon: Icons.badge_outlined,
                        label: 'Role',
                        value: authState.role?.toUpperCase() ?? '—',
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 24),

              // Connection settings
              _SectionHeader(title: 'Connection'),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerHigh,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                  side: BorderSide(
                      color: colorScheme.outlineVariant.withOpacity(0.4)),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      TextFormField(
                        controller: _urlController,
                        keyboardType: TextInputType.url,
                        autocorrect: false,
                        decoration: InputDecoration(
                          labelText: 'Backend URL',
                          hintText: 'http://localhost:8080',
                          prefixIcon:
                              const Icon(Icons.dns_outlined),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                          filled: true,
                          fillColor: colorScheme.surface,
                        ),
                        validator: (value) {
                          if (value == null || value.trim().isEmpty) {
                            return 'Backend URL is required';
                          }
                          final uri = Uri.tryParse(value.trim());
                          if (uri == null ||
                              (!uri.scheme.startsWith('http'))) {
                            return 'Enter a valid http/https URL';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 14),
                      TextFormField(
                        controller: _tokenController,
                        obscureText: _obscureToken,
                        autocorrect: false,
                        decoration: InputDecoration(
                          labelText: 'API Token override (optional)',
                          hintText: 'Leave blank to use login token',
                          prefixIcon:
                              const Icon(Icons.key_outlined),
                          suffixIcon: IconButton(
                            icon: Icon(_obscureToken
                                ? Icons.visibility_outlined
                                : Icons.visibility_off_outlined),
                            onPressed: () => setState(
                                () => _obscureToken = !_obscureToken),
                          ),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                          filled: true,
                          fillColor: colorScheme.surface,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 24),

              // Appearance
              _SectionHeader(title: 'Appearance'),
              Card(
                elevation: 0,
                color: colorScheme.surfaceContainerHigh,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                  side: BorderSide(
                      color: colorScheme.outlineVariant.withOpacity(0.4)),
                ),
                child: Padding(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Row(
                    children: [
                      Icon(Icons.palette_outlined,
                          color: colorScheme.onSurfaceVariant),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Text(
                          'Theme',
                          style: textTheme.bodyMedium?.copyWith(
                            color: colorScheme.onSurface,
                          ),
                        ),
                      ),
                      DropdownButton<ThemeMode>(
                        value: _selectedTheme,
                        underline: const SizedBox.shrink(),
                        onChanged: (mode) {
                          if (mode != null) {
                            setState(() => _selectedTheme = mode);
                          }
                        },
                        items: const [
                          DropdownMenuItem(
                            value: ThemeMode.dark,
                            child: Text('Dark'),
                          ),
                          DropdownMenuItem(
                            value: ThemeMode.light,
                            child: Text('Light'),
                          ),
                          DropdownMenuItem(
                            value: ThemeMode.system,
                            child: Text('System'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 28),

              // Save button
              SizedBox(
                height: 50,
                child: FilledButton.icon(
                  onPressed: settings.isSaving ? null : _save,
                  icon: settings.isSaving
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child:
                              CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.save_outlined),
                  label: const Text(
                    'Save Settings',
                    style: TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w600),
                  ),
                  style: FilledButton.styleFrom(
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                ),
              ),

              const SizedBox(height: 16),

              // Sign out button
              OutlinedButton.icon(
                onPressed: () async {
                  await ref.read(authProvider.notifier).logout();
                  if (context.mounted) {
                    context.go('/login');
                  }
                },
                icon: const Icon(Icons.logout_outlined),
                label: const Text('Sign Out'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: colorScheme.error,
                  side: BorderSide(color: colorScheme.error.withOpacity(0.5)),
                  minimumSize: const Size.fromHeight(48),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
              ),

              const SizedBox(height: 32),

              // Version footer
              Center(
                child: Text(
                  'TraceGuard EDR — Flutter Analyst UI',
                  style: textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Shared sub-widgets
// ---------------------------------------------------------------------------

class _SectionHeader extends StatelessWidget {
  final String title;

  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Text(
        title.toUpperCase(),
        style: textTheme.labelSmall?.copyWith(
          color: colorScheme.onSurfaceVariant,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.2,
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _InfoRow({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    return Row(
      children: [
        Icon(icon, size: 18, color: colorScheme.onSurfaceVariant),
        const SizedBox(width: 12),
        Text(
          label,
          style: textTheme.bodySmall?.copyWith(
            color: colorScheme.onSurfaceVariant,
          ),
        ),
        const Spacer(),
        Text(
          value,
          style: textTheme.bodyMedium?.copyWith(
            color: colorScheme.onSurface,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}
