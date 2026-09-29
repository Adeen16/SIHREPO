export interface Alert {
  flow_id: string;
  timestamp: number;
  threat_class: string;
  confidence: number;
  evidence: Record<string, any>;
  severity?: string;
  receivedAt?: number;
  fusion_reason?: string;
  all_detector_results?: Array<{
    detector: string;
    status: string;
    threat_type: string | null;
    confidence: number | null;
    evidence: Record<string, any>;
  }>;
}

export interface WindowMetrics {
  timestamp: number;
  packets_per_second: number;
  bytes_per_second: number;
  flows_per_second: number;
  active_flows: number;
}

export interface FlowHost {
  ip: string;
  protocol: string;
  last_seen: number;
  volume: number;
}

/** Polled from GET /status — not in WebSocket payload */
export interface SystemStatus {
  status: string;
  model_loaded: boolean;
  packets_processed: number;
  windows_completed: number;
  detections_generated: number;
  processing_errors: number;
  is_processing: boolean;
}

/** Polled from GET /model */
export interface ModelInfo {
  model_name: string;
  features_expected: number;
  features_list: string[];
}
