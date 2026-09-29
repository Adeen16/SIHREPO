export interface Alert {
  flow_id: string;
  timestamp: number;
  threat_class: string;
  confidence: number;
  evidence: Record<string, any>;
  severity?: string;
  receivedAt?: number;
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
