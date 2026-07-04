/*
 * Types for the sensor API's JSON (src/api.py). Shared by server and client
 * code; contains no secrets.
 */

export const THREAT_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type ThreatLevel = (typeof THREAT_LEVELS)[number];

/** Severity rank, LOW=0 ... CRITICAL=3 (mirrors the backend ThreatLevel order). */
export function threatRank(level: ThreatLevel): number {
  return THREAT_LEVELS.indexOf(level);
}

export function isThreatLevel(value: unknown): value is ThreatLevel {
  return typeof value === "string" && (THREAT_LEVELS as readonly string[]).includes(value);
}

/** One analyzed flow (DetectionResult.to_dict()). */
export type Detection = {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  threat_level: ThreatLevel;
  attack_type: string;
  confidence: number;
  mitre_techniques: string[];
  reasoning: string;
  ml_score: number;
  /** The 59 flow features; only present when requested */
  raw_features?: Record<string, number>;
};

export type ActionType = "BLOCK_IP" | "UNBLOCK_IP" | "ALERT" | "LOG" | (string & {});
export type ActionStatus = "SUCCESS" | "PARTIAL" | "FAILED" | "SKIPPED" | "PENDING" | (string & {});

/** A response the agent took (ResponseAction.to_dict()). */
export type ResponseAction = {
  timestamp: string;
  action_type: ActionType;
  target: string;
  status: ActionStatus;
  /** Varies by action: message/error/dry_run for blocks, title/level for
   *  alerts, the full detection (with features) for LOG actions */
  details: Record<string, unknown>;
};

export type Stats = {
  /** Not currently updated by the backend; don't display */
  packets_analyzed: number;
  flows_analyzed: number;
  threats_detected: number;
  critical_alerts: number;
  ips_blocked: number;
  start_time: string;
};

export type ModelInfo = {
  trained: boolean;
  trained_at: string | null;
  training_samples: number | null;
  /** Calibrated anomaly-score cut-offs; empty when untrained */
  thresholds: Partial<Record<ThreatLevel, number>>;
};

/** Settings.describe(): non-secret sensor configuration. */
export type SensorSettings = {
  dry_run: boolean;
  auto_block_critical: boolean;
  slack_configured: boolean;
  webhook_count: number;
  alert_cooldown_seconds: number;
  allowlist: string[];
  blocklist_file: string | null;
  model_path: string | null;
  thresholds: Partial<Record<ThreatLevel, number>>;
  log_level: string;
  max_upload_mb: number;
  api_key_configured: boolean;
  cors_origins: string[];
};

export type LiveStatus = {
  running: boolean;
  interface: string | null;
  started_at: string | null;
  stopped_at: string | null;
  flows: number;
  threats: number;
  error: string | null;
};

/** GET /api/live adds the interfaces available for capture. */
export type LiveInfo = LiveStatus & { interfaces: string[] };

export type SensorStatus = {
  version: string;
  /** Description of the running job (analysis/training), or null */
  busy: string | null;
  live: LiveStatus;
  stats: Stats;
  model: ModelInfo;
  settings: SensorSettings;
};

export type AnalyzeResult = {
  file: string;
  flows_analyzed: number;
  threats_detected: number;
  detections: Detection[];
  responses: ResponseAction[];
  stats: Stats;
  model_trained: boolean;
};

export type TrainResult = {
  model: ModelInfo;
  saved_to: string | null;
};

export type Blocklist = {
  ips: string[];
  dry_run: boolean;
};

export type ExportData = {
  export_time: string;
  stats: Stats;
  detections: Detection[];
  responses: ResponseAction[];
  blocklist: string[];
};
