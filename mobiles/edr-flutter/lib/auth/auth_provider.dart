import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:edr_flutter/models/models.dart';
import 'package:edr_flutter/network/edr_api.dart';

// ---------------------------------------------------------------------------
// Auth State
// ---------------------------------------------------------------------------

enum AuthStatus { unknown, unauthenticated, authenticated }

class AuthState {
  final AuthStatus status;
  final String? token;
  final String? email;
  final String? role;
  final String? errorMessage;

  const AuthState({
    this.status = AuthStatus.unknown,
    this.token,
    this.email,
    this.role,
    this.errorMessage,
  });

  bool get isAuthenticated => status == AuthStatus.authenticated;
  bool get isLoading => status == AuthStatus.unknown;

  AuthState copyWith({
    AuthStatus? status,
    String? token,
    String? email,
    String? role,
    String? errorMessage,
  }) {
    return AuthState(
      status: status ?? this.status,
      token: token ?? this.token,
      email: email ?? this.email,
      role: role ?? this.role,
      errorMessage: errorMessage,
    );
  }

  @override
  String toString() =>
      'AuthState(status: $status, email: $email, role: $role)';
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const _kTokenKey = 'edr_jwt_token';
const _kEmailKey = 'edr_user_email';
const _kRoleKey = 'edr_user_role';
const _kBackendUrlKey = 'edr_backend_url';
const _kDefaultBackendUrl = 'http://localhost:8080';

// ---------------------------------------------------------------------------
// Secure storage provider
// ---------------------------------------------------------------------------

final secureStorageProvider = Provider<FlutterSecureStorage>((ref) {
  return const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
});

// ---------------------------------------------------------------------------
// Shared prefs provider (async)
// ---------------------------------------------------------------------------

final sharedPrefsProvider = FutureProvider<SharedPreferences>((ref) async {
  return SharedPreferences.getInstance();
});

// ---------------------------------------------------------------------------
// Backend URL provider
// ---------------------------------------------------------------------------

final backendUrlProvider = StateProvider<String>((ref) {
  return _kDefaultBackendUrl;
});

// Reads saved URL from prefs and updates the backendUrlProvider
final backendUrlInitProvider = FutureProvider<String>((ref) async {
  final prefs = await SharedPreferences.getInstance();
  final url =
      prefs.getString(_kBackendUrlKey) ?? _kDefaultBackendUrl;
  // Update the state provider so dependent providers see the loaded value
  ref.read(backendUrlProvider.notifier).state = url;
  return url;
});

// ---------------------------------------------------------------------------
// Dio / API client provider
// ---------------------------------------------------------------------------

/// Creates and configures the Dio instance used by EdrApi.
/// The JWT interceptor reads the current token from authProvider on each request.
final apiClientProvider = Provider<Dio>((ref) {
  final backendUrl = ref.watch(backendUrlProvider);

  final dio = Dio(
    BaseOptions(
      baseUrl: backendUrl,
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 30),
      sendTimeout: const Duration(seconds: 15),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ),
  );

  // JWT interceptor: attach token from auth state on every request
  dio.interceptors.add(
    InterceptorsWrapper(
      onRequest: (options, handler) async {
        // Read token from secure storage each time to stay up to date
        const storage = FlutterSecureStorage();
        final token = await storage.read(key: _kTokenKey);
        if (token != null && token.isNotEmpty) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        handler.next(options);
      },
      onError: (error, handler) {
        handler.next(error);
      },
    ),
  );

  return dio;
});

/// Provides the EdrApi instance, which uses the configured Dio client.
final edrApiProvider = Provider<EdrApi>((ref) {
  final dio = ref.watch(apiClientProvider);
  return EdrApi(dio);
});

// ---------------------------------------------------------------------------
// Auth Notifier
// ---------------------------------------------------------------------------

class AuthNotifier extends StateNotifier<AuthState> {
  final FlutterSecureStorage _storage;
  final Ref _ref;

  AuthNotifier(this._storage, this._ref) : super(const AuthState());

  /// Attempt to restore a previously saved session.
  Future<void> tryRestoreSession() async {
    try {
      final token = await _storage.read(key: _kTokenKey);
      final email = await _storage.read(key: _kEmailKey);
      final role = await _storage.read(key: _kRoleKey);

      if (token != null && token.isNotEmpty) {
        state = AuthState(
          status: AuthStatus.authenticated,
          token: token,
          email: email,
          role: role ?? 'analyst',
        );
      } else {
        state = const AuthState(status: AuthStatus.unauthenticated);
      }
    } catch (_) {
      state = const AuthState(status: AuthStatus.unauthenticated);
    }
  }

  /// Log in with email + password. Saves JWT to secure storage on success.
  Future<void> login(String email, String password) async {
    state = const AuthState(status: AuthStatus.unknown);
    try {
      final api = _ref.read(edrApiProvider);
      final result = await api.login(email, password);

      final token = result['token']?.toString() ??
          result['access_token']?.toString() ??
          result['jwt']?.toString() ??
          '';

      if (token.isEmpty) {
        state = const AuthState(
          status: AuthStatus.unauthenticated,
          errorMessage: 'No token received from server.',
        );
        return;
      }

      final userRole = result['role']?.toString() ??
          result['user']?['role']?.toString() ??
          'analyst';
      final userEmail = result['email']?.toString() ??
          result['user']?['email']?.toString() ??
          email;

      await _storage.write(key: _kTokenKey, value: token);
      await _storage.write(key: _kEmailKey, value: userEmail);
      await _storage.write(key: _kRoleKey, value: userRole);

      state = AuthState(
        status: AuthStatus.authenticated,
        token: token,
        email: userEmail,
        role: userRole,
      );
    } on Exception catch (e) {
      state = AuthState(
        status: AuthStatus.unauthenticated,
        errorMessage: e.toString().replaceFirst('Exception: ', ''),
      );
    }
  }

  /// Log out and clear stored credentials.
  Future<void> logout() async {
    await _storage.delete(key: _kTokenKey);
    await _storage.delete(key: _kEmailKey);
    await _storage.delete(key: _kRoleKey);
    state = const AuthState(status: AuthStatus.unauthenticated);
  }

  /// Returns the current token (synchronous, from state).
  String? get currentToken => state.token;
}

// ---------------------------------------------------------------------------
// Auth provider
// ---------------------------------------------------------------------------

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  final storage = ref.watch(secureStorageProvider);
  return AuthNotifier(storage, ref);
});
