/**
 * TypeScript type definitions matching backend Pydantic schemas and models.
 */

export type LogSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';

export interface SecurityLog {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number | null;
  username: string | null;
  event_type: string;
  description: string | null;
  severity: LogSeverity;
  command_line: string | null;
  raw_log: string | null;
}

export interface SecurityLogListResponse {
  items: SecurityLog[];
  total: number;
  skip: number;
  limit: number;
}

export interface LogFilters {
  skip: number;
  limit: number;
  severity?: LogSeverity;
  event_type?: string;
  source_ip?: string;
}

export interface MitreTechniqueNested {
  id: number;
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface SecurityAlert {
  id: number;
  title: string;
  description: string | null;
  severity: AlertSeverity;
  status: AlertStatus;
  source_ip: string | null;
  rule_id: string | null;
  incident_start: string | null;
  incident_key: string | null;
  detection_time: string;
  mitre_technique_id: number | null;
  mitre_technique: MitreTechniqueNested | null;
}

export interface SecurityAlertListResponse {
  items: SecurityAlert[];
  total: number;
  skip: number;
  limit: number;
}

export interface AlertFilters {
  skip: number;
  limit: number;
  severity?: AlertSeverity;
  status?: AlertStatus;
}

export interface AlertUpdatePayload {
  status?: AlertStatus;
  severity?: AlertSeverity;
  description?: string;
}

export interface MitreTechnique {
  id: number;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string | null;
}

export interface MitreTechniqueListResponse {
  items: MitreTechnique[];
  total: number;
}

export interface MitreTechniqueStat {
  technique_id: string;
  technique_name: string;
  count: number;
}

export interface HourlyLogStat {
  hour: string;
  count: number;
}

export interface StatsSummary {
  total_logs: number;
  total_alerts: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  alerts_by_mitre: MitreTechniqueStat[];
  logs_by_event_type: Record<string, number>;
  log_counts_per_hour: HourlyLogStat[];
}

export interface DetectionRunResponse {
  rules_executed: number;
  total_alerts_created: number;
  alerts_per_rule: Record<string, number>;
}

export interface LogGenerateResponse {
  status: string;
  generated_count: number;
  seed: number | null;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}
