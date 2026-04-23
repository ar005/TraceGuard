export interface Agent {
  id: string;
  hostname: string;
  os: string;
  os_version: string;
  ip: string;
  agent_ver: string;
  first_seen: string;
  last_seen: string;
  is_online: boolean;
  config_ver: string;
  tags: string[];
  env: string;
  notes: string;
  winevent_config?: {
    channels?: Array<{
      name: string;
      event_ids: number[];
    }>;
  };
}

export interface Event {
  id: string;
  agent_id: string;
  hostname: string;
  event_type: string;
  timestamp: string;
  payload: Record<string, unknown>;
  received_at: string;
  severity: number;
  rule_id: string;
  alert_id: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: number;
  status: string;
  rule_id: string;
  rule_name: string;
  mitre_ids: string[];
  event_ids: string[];
  agent_id: string;
  hostname: string;
  first_seen: string;
  last_seen: string;
  assignee: string;
  notes: string;
  hit_count: number;
  incident_id: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: number;
  event_types: string[];
  conditions: RuleCondition[];
  mitre_ids: string[];
  created_at: string;
  updated_at: string;
  author: string;
  rule_type: string;
  threshold_count: number;
  threshold_window_s: number;
  group_by: string;
}

export interface RuleCondition {
  field: string;
  op: string;
  value: unknown;
}

export interface SuppressionRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  event_types: string[];
  conditions: RuleCondition[];
  created_at: string;
  updated_at: string;
  author: string;
  hit_count: number;
  last_hit_at?: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: number;
  status: string;
  alert_ids: string[];
  agent_ids: string[];
  hostnames: string[];
  mitre_ids: string[];
  alert_count: number;
  first_seen: string;
  last_seen: string;
  assignee: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface IOC {
  id: string;
  type: string;
  value: string;
  source: string;
  severity: number;
  description: string;
  tags: string[];
  enabled: boolean;
  expires_at?: string;
  created_at: string;
  hit_count: number;
  last_hit_at?: string;
}

export interface IOCStats {
  total_iocs: number;
  ip_count: number;
  domain_count: number;
  hash_count: number;
  enabled_count: number;
  total_hits: number;
}

export interface Vulnerability {
  id: number;
  agent_id: string;
  package_name: string;
  package_version: string;
  cve_id: string;
  severity: string;
  description: string;
  fixed_version: string;
  detected_at: string;
}

export interface VulnStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  enabled: boolean;
  created_at: string;
  last_login_at?: string;
  created_by: string;
}

export interface DashboardData {
  agents_total: number;
  agents_online: number;
  events_24h: number;
  alert_stats: {
    total: number;
    open: number;
    investigating: number;
    closed: number;
    by_severity: Record<string, number>;
  };
  recent_alerts: Alert[];
}

export interface BacktestResult {
  rule_id: string;
  total_scanned: number;
  matched: number;
  match_rate: number;
  window_hours: number;
  samples: Event[];
}

export interface LLMSettings {
  provider: string;
  model: string;
  base_url: string;
  api_key: string;
  enabled: boolean;
}

export interface RetentionSettings {
  events_days: number;
  alerts_days: number;
}

export interface IOCFeed {
  name: string;
  url: string;
  type: string;
  enabled: boolean;
  last_sync?: string;
}

export interface IOCSourceStats {
  source: string;
  total: number;
  ip_count: number;
  domain_count: number;
  hash_count: number;
  enabled_count: number;
  total_hits: number;
  first_seen: string;
  last_updated: string;
}

export interface YARARule {
  id: string;
  name: string;
  description: string;
  rule_text: string;
  enabled: boolean;
  severity: number;
  mitre_ids: string[];
  tags: string[];
  author: string;
  created_at: string;
  updated_at: string;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  severity: number;
  meta: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface IncidentGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
