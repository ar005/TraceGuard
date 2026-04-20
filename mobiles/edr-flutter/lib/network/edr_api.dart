import 'package:dio/dio.dart';
import 'package:edr_flutter/models/models.dart';

class EdrApi {
  final Dio _dio;

  EdrApi(this._dio);

  // ---------------------------------------------------------------------------
  // Auth
  // ---------------------------------------------------------------------------

  Future<Map<String, dynamic>> login(String email, String password) async {
    try {
      final response = await _dio.post(
        '/api/v1/auth/login',
        data: {'email': email, 'password': password},
      );
      final data = response.data;
      if (data is Map<String, dynamic>) return data;
      throw Exception('Unexpected login response format');
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<String> getSseTicket() async {
    try {
      final response = await _dio.post('/api/v1/auth/sse-ticket');
      final data = response.data;
      if (data is Map<String, dynamic>) {
        return data['ticket']?.toString() ??
            data['token']?.toString() ??
            data['sse_ticket']?.toString() ??
            '';
      }
      return data?.toString() ?? '';
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Dashboard
  // ---------------------------------------------------------------------------

  Future<DashboardStats> getDashboard() async {
    try {
      final response = await _dio.get('/api/v1/dashboard');
      final data = response.data;
      if (data is Map<String, dynamic>) {
        return DashboardStats.fromJson(data);
      }
      return DashboardStats.empty();
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Agents
  // ---------------------------------------------------------------------------

  Future<List<Agent>> getAgents() async {
    try {
      final response = await _dio.get('/api/v1/agents');
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(Agent.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['agents'] is List) {
        return (data['agents'] as List)
            .whereType<Map<String, dynamic>>()
            .map(Agent.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<Agent> getAgent(String id) async {
    try {
      final response = await _dio.get('/api/v1/agents/$id');
      final data = response.data;
      if (data is Map<String, dynamic>) return Agent.fromJson(data);
      throw Exception('Unexpected agent response format');
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Alerts
  // ---------------------------------------------------------------------------

  Future<List<Alert>> getAlerts({
    String? agentId,
    String? severity,
    String? status,
    int? limit,
  }) async {
    try {
      final queryParams = <String, dynamic>{};
      if (agentId != null && agentId.isNotEmpty) {
        queryParams['agent_id'] = agentId;
      }
      if (severity != null && severity.isNotEmpty && severity != 'ALL') {
        queryParams['severity'] = severity.toLowerCase();
      }
      if (status != null && status.isNotEmpty && status != 'ALL') {
        queryParams['status'] = status.toLowerCase();
      }
      if (limit != null) queryParams['limit'] = limit;

      final response = await _dio.get(
        '/api/v1/alerts',
        queryParameters: queryParams.isNotEmpty ? queryParams : null,
      );
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(Alert.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['alerts'] is List) {
        return (data['alerts'] as List)
            .whereType<Map<String, dynamic>>()
            .map(Alert.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<Alert> getAlert(String id) async {
    try {
      final response = await _dio.get('/api/v1/alerts/$id');
      final data = response.data;
      if (data is Map<String, dynamic>) return Alert.fromJson(data);
      throw Exception('Unexpected alert response format');
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<void> updateAlertStatus(String id, String status) async {
    try {
      await _dio.put(
        '/api/v1/alerts/$id',
        data: {'status': status},
      );
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  /// Returns related events for an alert. The backend returns event records
  /// but we reuse the Alert model since the prompt specifies List<Alert>.
  Future<List<Alert>> getAlertEvents(String alertId) async {
    try {
      final response = await _dio.get('/api/v1/alerts/$alertId/events');
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(Alert.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['events'] is List) {
        return (data['events'] as List)
            .whereType<Map<String, dynamic>>()
            .map(Alert.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Incidents
  // ---------------------------------------------------------------------------

  Future<List<Incident>> getIncidents() async {
    try {
      final response = await _dio.get('/api/v1/incidents');
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(Incident.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['incidents'] is List) {
        return (data['incidents'] as List)
            .whereType<Map<String, dynamic>>()
            .map(Incident.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<Incident> getIncident(String id) async {
    try {
      final response = await _dio.get('/api/v1/incidents/$id');
      final data = response.data;
      if (data is Map<String, dynamic>) return Incident.fromJson(data);
      throw Exception('Unexpected incident response format');
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  Future<List<EventRecord>> getEvents({
    String? agentId,
    String? eventType,
    int limit = 100,
  }) async {
    try {
      final queryParams = <String, dynamic>{'limit': limit};
      if (agentId != null && agentId.isNotEmpty) {
        queryParams['agent_id'] = agentId;
      }
      if (eventType != null && eventType.isNotEmpty) {
        queryParams['event_type'] = eventType;
      }

      final response = await _dio.get(
        '/api/v1/events',
        queryParameters: queryParams,
      );
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(EventRecord.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['events'] is List) {
        return (data['events'] as List)
            .whereType<Map<String, dynamic>>()
            .map(EventRecord.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Threat Hunting
  // ---------------------------------------------------------------------------

  Future<HuntResult> hunt(String query) async {
    try {
      final response = await _dio.post(
        '/api/v1/hunt',
        data: {'query': query},
      );
      final data = response.data;
      if (data is Map<String, dynamic>) return HuntResult.fromJson(data);
      return HuntResult.empty();
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Live Response
  // ---------------------------------------------------------------------------

  Future<List<LiveResponseAgent>> getLiveResponseAgents() async {
    try {
      final response = await _dio.get('/api/v1/liveresponse/agents');
      final data = response.data;
      if (data is List) {
        return data
            .whereType<Map<String, dynamic>>()
            .map(LiveResponseAgent.fromJson)
            .toList();
      }
      if (data is Map<String, dynamic> && data['agents'] is List) {
        return (data['agents'] as List)
            .whereType<Map<String, dynamic>>()
            .map(LiveResponseAgent.fromJson)
            .toList();
      }
      return [];
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  Future<Map<String, dynamic>> sendLiveResponseCommand({
    required String agentId,
    required String command,
    List<String> args = const [],
  }) async {
    try {
      final response = await _dio.post(
        '/api/v1/liveresponse',
        data: {
          'agent_id': agentId,
          'command': command,
          'args': args,
        },
      );
      final data = response.data;
      if (data is Map<String, dynamic>) return data;
      return {'output': data?.toString() ?? ''};
    } on DioException catch (e) {
      throw _handleDioError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  Exception _handleDioError(DioException e) {
    switch (e.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        return Exception('Connection timed out. Please check your network.');
      case DioExceptionType.connectionError:
        return Exception(
            'Cannot reach the backend. Check the URL in Settings.');
      case DioExceptionType.badResponse:
        final statusCode = e.response?.statusCode ?? 0;
        final message = _extractErrorMessage(e.response?.data);
        if (statusCode == 401) {
          return Exception('Unauthorized: $message');
        }
        if (statusCode == 403) {
          return Exception('Forbidden: $message');
        }
        if (statusCode == 404) {
          return Exception('Not found: $message');
        }
        if (statusCode == 422) {
          return Exception('Validation error: $message');
        }
        if (statusCode >= 500) {
          return Exception('Server error ($statusCode): $message');
        }
        return Exception('Request failed ($statusCode): $message');
      case DioExceptionType.cancel:
        return Exception('Request was cancelled.');
      default:
        return Exception(e.message ?? 'An unexpected error occurred.');
    }
  }

  String _extractErrorMessage(dynamic data) {
    if (data == null) return 'Unknown error';
    if (data is Map<String, dynamic>) {
      return data['error']?.toString() ??
          data['message']?.toString() ??
          data['detail']?.toString() ??
          data.toString();
    }
    return data.toString();
  }
}
