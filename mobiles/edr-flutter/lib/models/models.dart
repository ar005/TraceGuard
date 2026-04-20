import 'package:flutter/foundation.dart';

class Agent {
  final String id;
  final String hostname;
  final String os;
  final String ip;
  final String status;
  final String agentVer;
  final DateTime? lastSeen;

  const Agent({
    required this.id,
    required this.hostname,
    required this.os,
    required this.ip,
    required this.status,
    required this.agentVer,
    this.lastSeen,
  });

  factory Agent.fromJson(Map<String, dynamic> json) {
    return Agent(
      id: json['id']?.toString() ?? '',
      hostname: json['hostname']?.toString() ?? '',
      os: json['os']?.toString() ?? '',
      ip: json['ip']?.toString() ?? json['ip_address']?.toString() ?? '',
      status: json['status']?.toString() ?? 'offline',
      agentVer: json['agent_ver']?.toString() ??
          json['agent_version']?.toString() ??
          '',
      lastSeen: json['last_seen'] != null
          ? DateTime.tryParse(json['last_seen'].toString())
          : null,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'hostname': hostname,
        'os': os,
        'ip': ip,
        'status': status,
        'agent_ver': agentVer,
        'last_seen': lastSeen?.toIso8601String(),
      };

  bool get isOnline => status.toLowerCase() == 'online';

  Agent copyWith({
    String? id,
    String? hostname,
    String? os,
    String? ip,
    String? status,
    String? agentVer,
    DateTime? lastSeen,
  }) {
    return Agent(
      id: id ?? this.id,
      hostname: hostname ?? this.hostname,
      os: os ?? this.os,
      ip: ip ?? this.ip,
      status: status ?? this.status,
      agentVer: agentVer ?? this.agentVer,
      lastSeen: lastSeen ?? this.lastSeen,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Agent && other.id == id);

  @override
  int get hashCode => id.hashCode;
}

class Alert {
  final String id;
  final String agentId;
  final String ruleName;
  final String severity;
  final String status;
  final DateTime createdAt;
  final List<String> mitreTactics;
  final List<String> mitreTechniques;
  final String? description;

  const Alert({
    required this.id,
    required this.agentId,
    required this.ruleName,
    required this.severity,
    required this.status,
    required this.createdAt,
    required this.mitreTactics,
    required this.mitreTechniques,
    this.description,
  });

  factory Alert.fromJson(Map<String, dynamic> json) {
    List<String> parseTactics(dynamic value) {
      if (value == null) return [];
      if (value is List) return value.map((e) => e.toString()).toList();
      if (value is String && value.isNotEmpty) return [value];
      return [];
    }

    return Alert(
      id: json['id']?.toString() ?? '',
      agentId: json['agent_id']?.toString() ?? '',
      ruleName: json['rule_name']?.toString() ?? '',
      severity: json['severity']?.toString() ?? 'low',
      status: json['status']?.toString() ?? 'open',
      createdAt: json['created_at'] != null
          ? DateTime.tryParse(json['created_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
      mitreTactics: parseTactics(json['mitre_tactics']),
      mitreTechniques: parseTactics(json['mitre_techniques']),
      description: json['description']?.toString(),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'agent_id': agentId,
        'rule_name': ruleName,
        'severity': severity,
        'status': status,
        'created_at': createdAt.toIso8601String(),
        'mitre_tactics': mitreTactics,
        'mitre_techniques': mitreTechniques,
        'description': description,
      };

  Alert copyWith({
    String? id,
    String? agentId,
    String? ruleName,
    String? severity,
    String? status,
    DateTime? createdAt,
    List<String>? mitreTactics,
    List<String>? mitreTechniques,
    String? description,
  }) {
    return Alert(
      id: id ?? this.id,
      agentId: agentId ?? this.agentId,
      ruleName: ruleName ?? this.ruleName,
      severity: severity ?? this.severity,
      status: status ?? this.status,
      createdAt: createdAt ?? this.createdAt,
      mitreTactics: mitreTactics ?? this.mitreTactics,
      mitreTechniques: mitreTechniques ?? this.mitreTechniques,
      description: description ?? this.description,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Alert && other.id == id);

  @override
  int get hashCode => id.hashCode;
}

class Incident {
  final String id;
  final String agentId;
  final String severity;
  final String status;
  final DateTime createdAt;
  final List<String> alertIds;
  final List<String> mitreIds;
  final int alertCount;

  const Incident({
    required this.id,
    required this.agentId,
    required this.severity,
    required this.status,
    required this.createdAt,
    required this.alertIds,
    required this.mitreIds,
    required this.alertCount,
  });

  factory Incident.fromJson(Map<String, dynamic> json) {
    List<String> parseList(dynamic value) {
      if (value == null) return [];
      if (value is List) return value.map((e) => e.toString()).toList();
      if (value is String && value.isNotEmpty) return [value];
      return [];
    }

    return Incident(
      id: json['id']?.toString() ?? '',
      agentId: json['agent_id']?.toString() ?? '',
      severity: json['severity']?.toString() ?? 'low',
      status: json['status']?.toString() ?? 'open',
      createdAt: json['created_at'] != null
          ? DateTime.tryParse(json['created_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
      alertIds: parseList(json['alert_ids']),
      mitreIds: parseList(json['mitre_ids']),
      alertCount: (json['alert_count'] as num?)?.toInt() ??
          parseList(json['alert_ids']).length,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'agent_id': agentId,
        'severity': severity,
        'status': status,
        'created_at': createdAt.toIso8601String(),
        'alert_ids': alertIds,
        'mitre_ids': mitreIds,
        'alert_count': alertCount,
      };

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Incident && other.id == id);

  @override
  int get hashCode => id.hashCode;
}

class EventRecord {
  final String id;
  final String agentId;
  final String eventType;
  final String hostname;
  final DateTime timestamp;
  final String payload;

  const EventRecord({
    required this.id,
    required this.agentId,
    required this.eventType,
    required this.hostname,
    required this.timestamp,
    required this.payload,
  });

  factory EventRecord.fromJson(Map<String, dynamic> json) {
    String extractPayload(Map<String, dynamic> json) {
      if (json['payload'] != null) return json['payload'].toString();
      // If payload is embedded in data fields, serialize relevant parts
      final excluded = {'id', 'agent_id', 'event_type', 'hostname', 'timestamp'};
      final payloadMap = <String, dynamic>{};
      for (final key in json.keys) {
        if (!excluded.contains(key)) {
          payloadMap[key] = json[key];
        }
      }
      if (payloadMap.isEmpty) return '{}';
      // Simple serialization without dart:convert to avoid import issues
      return payloadMap.toString();
    }

    return EventRecord(
      id: json['id']?.toString() ?? '',
      agentId: json['agent_id']?.toString() ?? '',
      eventType: json['event_type']?.toString() ?? '',
      hostname: json['hostname']?.toString() ?? '',
      timestamp: json['timestamp'] != null
          ? DateTime.tryParse(json['timestamp'].toString()) ?? DateTime.now()
          : DateTime.now(),
      payload: extractPayload(json),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'agent_id': agentId,
        'event_type': eventType,
        'hostname': hostname,
        'timestamp': timestamp.toIso8601String(),
        'payload': payload,
      };

  String get payloadPreview {
    if (payload.length <= 80) return payload;
    return '${payload.substring(0, 80)}...';
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is EventRecord && other.id == id);

  @override
  int get hashCode => id.hashCode;
}

class DashboardStats {
  final int totalAgents;
  final int onlineAgents;
  final int openAlerts;
  final int criticalAlerts;
  final int eventsToday;

  const DashboardStats({
    required this.totalAgents,
    required this.onlineAgents,
    required this.openAlerts,
    required this.criticalAlerts,
    required this.eventsToday,
  });

  factory DashboardStats.fromJson(Map<String, dynamic> json) {
    return DashboardStats(
      totalAgents: (json['total_agents'] as num?)?.toInt() ?? 0,
      onlineAgents: (json['online_agents'] as num?)?.toInt() ?? 0,
      openAlerts: (json['open_alerts'] as num?)?.toInt() ?? 0,
      criticalAlerts: (json['critical_alerts'] as num?)?.toInt() ?? 0,
      eventsToday: (json['events_today'] as num?)?.toInt() ?? 0,
    );
  }

  factory DashboardStats.empty() {
    return const DashboardStats(
      totalAgents: 0,
      onlineAgents: 0,
      openAlerts: 0,
      criticalAlerts: 0,
      eventsToday: 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'total_agents': totalAgents,
        'online_agents': onlineAgents,
        'open_alerts': openAlerts,
        'critical_alerts': criticalAlerts,
        'events_today': eventsToday,
      };
}

class LiveResponseAgent {
  final String agentId;
  final String hostname;
  final String os;
  final String status;

  const LiveResponseAgent({
    required this.agentId,
    required this.hostname,
    required this.os,
    required this.status,
  });

  factory LiveResponseAgent.fromJson(Map<String, dynamic> json) {
    return LiveResponseAgent(
      agentId: json['agent_id']?.toString() ?? json['id']?.toString() ?? '',
      hostname: json['hostname']?.toString() ?? '',
      os: json['os']?.toString() ?? '',
      status: json['status']?.toString() ?? 'offline',
    );
  }

  Map<String, dynamic> toJson() => {
        'agent_id': agentId,
        'hostname': hostname,
        'os': os,
        'status': status,
      };

  bool get isOnline => status.toLowerCase() == 'online';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is LiveResponseAgent && other.agentId == agentId);

  @override
  int get hashCode => agentId.hashCode;
}

class HuntResult {
  final int total;
  final List<Map<String, dynamic>> rows;

  const HuntResult({
    required this.total,
    required this.rows,
  });

  factory HuntResult.fromJson(Map<String, dynamic> json) {
    final rawRows = json['rows'];
    List<Map<String, dynamic>> rows = [];
    if (rawRows is List) {
      for (final row in rawRows) {
        if (row is Map<String, dynamic>) {
          rows.add(row);
        } else if (row is Map) {
          rows.add(Map<String, dynamic>.from(row));
        }
      }
    }

    return HuntResult(
      total: (json['total'] as num?)?.toInt() ?? rows.length,
      rows: rows,
    );
  }

  factory HuntResult.empty() {
    return const HuntResult(total: 0, rows: []);
  }

  Map<String, dynamic> toJson() => {
        'total': total,
        'rows': rows,
      };
}
