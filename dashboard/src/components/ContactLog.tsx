import React, { useState } from 'react';
import { format } from 'date-fns';
import type { Alert, ModelInfo } from '../types';

interface ContactLogProps {
  alerts: Alert[];
  uploadError: string | null;
  modelInfo?: ModelInfo | null;
}

// Status colors — red for detected, white/dim for everything else
const STATUS_COLOR: Record<string, string> = {
  DETECTED:          '#D14B32',
  UNVALIDATED:       'rgba(255,255,255,0.62)',
  NOT_DETECTED:      'rgba(255,255,255,0.28)',
  INSUFFICIENT_DATA: 'rgba(255,255,255,0.28)',
  BENIGN:            'rgba(255,255,255,0.42)',
  error:             '#D14B32',
};

const STATUS_LABEL: Record<string, string> = {
  DETECTED:          'DETECT',
  UNVALIDATED:       'UNVAL.',
  NOT_DETECTED:      'CLEAR',
  INSUFFICIENT_DATA: 'INSUF.',
  BENIGN:            'BENIGN',
  error:             'ERROR',
};

function isHighSeverity(alert: Alert): boolean {
  return alert.severity === 'HIGH' || alert.severity === 'CRITICAL' || alert.confidence >= 0.9;
}

/** Render DNS fields from evidence if present */
function DnsFields({ evidence }: { evidence: Record<string, any> }) {
  const fields = [
    evidence.domain_entropy_avg != null && { k: 'Domain Entropy (avg)', v: Number(evidence.domain_entropy_avg).toFixed(3) },
    evidence.domain_length_avg != null && { k: 'Domain Length (avg)', v: Number(evidence.domain_length_avg).toFixed(1) },
    evidence.unique_queries_across_windows != null && { k: 'Unique DNS Queries', v: String(evidence.unique_queries_across_windows) },
    evidence.high_entropy_queries != null && { k: 'High-Entropy Queries', v: String(evidence.high_entropy_queries) },
    evidence.dns_query_name != null && { k: 'Last Query Name', v: String(evidence.dns_query_name) },
  ].filter(Boolean) as Array<{ k: string; v: string }>;

  if (fields.length === 0) return null;
  return (
    <div style={{ marginTop: '8px' }}>
      <FieldGroupLabel>DNS Signal</FieldGroupLabel>
      {fields.map(f => <KVRow key={f.k} label={f.k} value={f.v} />)}
    </div>
  );
}

/** Render TLS fields from evidence if present */
function TlsFields({ evidence }: { evidence: Record<string, any> }) {
  const fields = [
    evidence.tls_sni_present != null && { k: 'SNI Present', v: String(evidence.tls_sni_present) },
    evidence.windows_seen != null && { k: 'TLS Sessions Seen', v: String(evidence.windows_seen) },
    evidence.total_bytes != null && { k: 'Total TLS Bytes', v: Number(evidence.total_bytes).toLocaleString() },
    evidence.tls_sni != null && { k: 'SNI Hostname', v: String(evidence.tls_sni) },
    evidence.tls_version != null && { k: 'TLS Version', v: String(evidence.tls_version) },
    evidence.tls_cipher_suites_count != null && { k: 'Cipher Suites', v: String(evidence.tls_cipher_suites_count) },
  ].filter(Boolean) as Array<{ k: string; v: string }>;

  if (fields.length === 0) return null;
  return (
    <div style={{ marginTop: '8px' }}>
      <FieldGroupLabel>TLS Signal</FieldGroupLabel>
      {fields.map(f => <KVRow key={f.k} label={f.k} value={f.v} />)}
    </div>
  );
}

const FieldGroupLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: '8px',
      letterSpacing: '0.22em',
      textTransform: 'uppercase',
      color: 'rgba(255,255,255,0.28)',
      marginBottom: '4px',
    }}
  >
    {children}
  </div>
);

const KVRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px', marginBottom: '2px' }}>
    <span
      style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '9px',
        color: 'rgba(255,255,255,0.42)',
        letterSpacing: '0.06em',
        flexShrink: 0,
      }}
    >
      {label}
    </span>
    <span
      style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '9px',
        color: '#fff',
        letterSpacing: '0.08em',
        textAlign: 'right',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        maxWidth: '150px',
      }}
      title={value}
    >
      {value}
    </span>
  </div>
);

export const ContactLog: React.FC<ContactLogProps> = ({ alerts, uploadError, modelInfo }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (uploadError) {
    return (
      <div style={{ padding: '16px' }}>
        <div
          style={{
            border: '1px solid #D14B32',
            background: 'rgba(209,75,50,0.08)',
            padding: '12px',
            marginBottom: '12px',
          }}
        >
          <div
            className="readout"
            style={{ fontSize: '9px', color: '#D14B32', marginBottom: '6px' }}
          >
            ⚠ UPLOAD FAILED
          </div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#D14B32', wordBreak: 'break-all' }}>
            {uploadError}
          </div>
        </div>
        <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'rgba(255,255,255,0.28)', letterSpacing: '0.08em' }}>
          Upload a valid .pcap capture file.
        </p>
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', padding: '16px' }}>
        <span
          className="readout"
          style={{ fontSize: '9px', color: 'rgba(255,255,255,0.28)' }}
        >
          NO CONTACTS LOGGED
        </span>
      </div>
    );
  }

  const toggleExpand = (id: string) => {
    setExpandedId(prev => prev === id ? null : id);
  };

  return (
    <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
      {alerts.map((alert, idx) => {
        const uiId = `${alert.flow_id}-${alert.timestamp}-${idx}`;
        const isExpanded = expandedId === uiId;
        const high = isHighSeverity(alert);
        const ev = alert.evidence || {};
        const isMlAssisted = alert.all_detector_results?.some(d =>
          d.detector === 'DDoSDetector' && d.status === 'DETECTED' && d.confidence != null
        );

        return (
          <li
            key={uiId}
            onClick={() => toggleExpand(uiId)}
            style={{
              borderBottom: '1px solid rgba(255,255,255,0.14)',
              borderLeft: high ? '2px solid #D14B32' : '2px solid transparent',
              cursor: 'pointer',
              background: high && isExpanded ? 'rgba(209,75,50,0.06)' : 'transparent',
              transition: 'background 0.2s',
            }}
          >
            {/* ── Summary row ── */}
            <div style={{ padding: '8px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                <span
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '9px',
                    color: 'rgba(255,255,255,0.42)',
                    letterSpacing: '0.08em',
                    flexShrink: 0,
                  }}
                >
                  {format(new Date(alert.timestamp * 1000), 'HH:mm:ss.SSS')}
                </span>
                {isMlAssisted && (
                  <span
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '7px',
                      letterSpacing: '0.14em',
                      textTransform: 'uppercase',
                      border: '1px solid rgba(255,255,255,0.26)',
                      padding: '1px 4px',
                      color: 'rgba(255,255,255,0.42)',
                      flexShrink: 0,
                    }}
                  >
                    ML
                  </span>
                )}
              </div>
              <div
                style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '10px',
                  color: 'rgba(255,255,255,0.42)',
                  marginBottom: '4px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  letterSpacing: '0.04em',
                }}
                title={alert.flow_id}
              >
                {alert.flow_id}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '11px',
                    fontWeight: 500,
                    letterSpacing: '0.1em',
                    color: high ? '#D14B32' : '#fff',
                    textTransform: 'uppercase',
                  }}
                  title={alert.threat_class}
                >
                  {alert.threat_class}
                </span>
                <span
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '10px',
                    color: 'rgba(255,255,255,0.42)',
                    letterSpacing: '0.08em',
                  }}
                >
                  {(alert.confidence * 100).toFixed(0)}%
                </span>
              </div>
              {alert.severity && (
                <div style={{ marginTop: '3px' }}>
                  <span
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '8px',
                      letterSpacing: '0.14em',
                      textTransform: 'uppercase',
                      border: `1px solid ${high ? '#D14B32' : 'rgba(255,255,255,0.14)'}`,
                      padding: '1px 5px',
                      color: high ? '#D14B32' : 'rgba(255,255,255,0.42)',
                    }}
                  >
                    {alert.severity}
                  </span>
                </div>
              )}
            </div>

            {/* ── Expanded Signal Detail panel ── */}
            <div
              style={{
                maxHeight: isExpanded ? '800px' : '0',
                overflow: 'hidden',
                transition: 'max-height 0.3s cubic-bezier(0.16,1,0.3,1)',
              }}
            >
              <div
                style={{
                  padding: '10px 12px 12px',
                  borderTop: '1px solid rgba(255,255,255,0.14)',
                  background: 'rgba(255,255,255,0.02)',
                }}
              >

                {/* Primary evidence */}
                {ev.reason && (
                  <div style={{ marginBottom: '10px' }}>
                    <FieldGroupLabel>Evidence</FieldGroupLabel>
                    <div
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '10px',
                        color: 'rgba(255,255,255,0.62)',
                        lineHeight: 1.5,
                        letterSpacing: '0.04em',
                      }}
                    >
                      {ev.reason}
                    </div>
                  </div>
                )}

                {/* Numeric evidence fields (non-reason) */}
                {Object.keys(ev).length > 0 && (
                  <div style={{ marginBottom: '8px' }}>
                    {ev.packets_per_sec != null && <KVRow label="Packets/sec" value={Number(ev.packets_per_sec).toFixed(1)} />}
                    {ev.bytes_per_sec != null && <KVRow label="Bytes/sec" value={Number(ev.bytes_per_sec).toFixed(0)} />}
                    {ev.flows_to_dst != null && <KVRow label="Flows to dest" value={String(ev.flows_to_dst)} />}
                    {ev.unique_destination_ports != null && <KVRow label="Unique dest ports" value={String(ev.unique_destination_ports)} />}
                    {ev.unique_destination_ips != null && <KVRow label="Unique dest IPs" value={String(ev.unique_destination_ips)} />}
                    {ev.outbound_bytes != null && <KVRow label="Outbound bytes" value={Number(ev.outbound_bytes).toLocaleString()} />}
                    {ev.inbound_bytes != null && <KVRow label="Inbound bytes" value={Number(ev.inbound_bytes).toLocaleString()} />}
                    {ev.outbound_inbound_ratio != null && <KVRow label="Out/In ratio" value={Number(ev.outbound_inbound_ratio).toFixed(1)} />}
                    {ev.periodicity_cv != null && <KVRow label="Timing CV" value={Number(ev.periodicity_cv).toFixed(4)} />}
                    {ev.windows_seen != null && ev.observation_span == null && <KVRow label="Windows seen" value={String(ev.windows_seen)} />}
                    {ev.observation_span != null && <KVRow label="Observation span" value={`${Number(ev.observation_span).toFixed(1)}s`} />}
                    {ev.packet_count != null && <KVRow label="Packet count" value={String(ev.packet_count)} />}
                    {ev.dst_ip != null && <KVRow label="Beacon target" value={String(ev.dst_ip)} />}
                    {ev.dst_port != null && <KVRow label="Dest port" value={String(ev.dst_port)} />}
                  </div>
                )}

                {/* DNS Signal Detail — only shown if evidence contains DNS fields */}
                <DnsFields evidence={ev} />

                {/* TLS Signal Detail — only shown if evidence contains TLS fields */}
                <TlsFields evidence={ev} />

                {/* Fusion reason */}
                {alert.fusion_reason && (
                  <div
                    style={{
                      marginTop: '8px',
                      padding: '6px 8px',
                      background: 'rgba(255,255,255,0.04)',
                      borderLeft: '2px solid rgba(255,255,255,0.14)',
                    }}
                  >
                    <FieldGroupLabel>Fusion Decision</FieldGroupLabel>
                    <div
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '9px',
                        color: 'rgba(255,255,255,0.62)',
                        letterSpacing: '0.06em',
                      }}
                    >
                      {alert.fusion_reason}
                    </div>
                  </div>
                )}

                {/* 6-detector breakdown */}
                {alert.all_detector_results && alert.all_detector_results.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <FieldGroupLabel>Detector Breakdown</FieldGroupLabel>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr>
                          {['Detector', 'Status', 'Conf.'].map(h => (
                            <th
                              key={h}
                              style={{
                                fontFamily: 'JetBrains Mono, monospace',
                                fontSize: '7px',
                                letterSpacing: '0.14em',
                                textTransform: 'uppercase',
                                color: 'rgba(255,255,255,0.28)',
                                fontWeight: 400,
                                textAlign: h === 'Conf.' ? 'right' : 'left',
                                paddingBottom: '4px',
                              }}
                            >
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {alert.all_detector_results.map((dr, i) => {
                          const isDetected = dr.status === 'DETECTED';
                          return (
                            <tr
                              key={i}
                              style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}
                            >
                              <td
                                style={{
                                  fontFamily: 'JetBrains Mono, monospace',
                                  fontSize: '8px',
                                  color: 'rgba(255,255,255,0.42)',
                                  padding: '3px 6px 3px 0',
                                  letterSpacing: '0.04em',
                                }}
                              >
                                {dr.detector.replace('Detector', '')}
                              </td>
                              <td
                                style={{
                                  fontFamily: 'JetBrains Mono, monospace',
                                  fontSize: '8px',
                                  color: STATUS_COLOR[dr.status] ?? 'rgba(255,255,255,0.28)',
                                  padding: '3px 6px 3px 0',
                                  letterSpacing: '0.1em',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                }}
                              >
                                <span
                                  style={{
                                    display: 'inline-block',
                                    width: '5px',
                                    height: '5px',
                                    background: isDetected ? '#D14B32' : 'transparent',
                                    border: `1px solid ${isDetected ? '#D14B32' : 'rgba(255,255,255,0.20)'}`,
                                    flexShrink: 0,
                                  }}
                                />
                                {STATUS_LABEL[dr.status] ?? dr.status}
                              </td>
                              <td
                                style={{
                                  fontFamily: 'JetBrains Mono, monospace',
                                  fontSize: '8px',
                                  color: 'rgba(255,255,255,0.42)',
                                  padding: '3px 0',
                                  textAlign: 'right',
                                  letterSpacing: '0.06em',
                                }}
                              >
                                {dr.confidence != null ? `${(dr.confidence * 100).toFixed(0)}%` : '—'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>

                    {/* ML diagnostics — shown if modelInfo available */}
                    {modelInfo && (
                      <div
                        style={{
                          marginTop: '8px',
                          paddingTop: '6px',
                          borderTop: '1px solid rgba(255,255,255,0.08)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '8px',
                            color: 'rgba(255,255,255,0.28)',
                            letterSpacing: '0.1em',
                            textTransform: 'uppercase',
                          }}
                        >
                          ML Engine
                        </span>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '8px',
                            color: 'rgba(255,255,255,0.42)',
                            letterSpacing: '0.06em',
                          }}
                        >
                          {modelInfo.model_name} · {modelInfo.features_expected} features
                        </span>
                      </div>
                    )}
                  </div>
                )}

              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
};
