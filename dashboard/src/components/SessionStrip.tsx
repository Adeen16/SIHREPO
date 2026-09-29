import React from 'react';
import type { SystemStatus, ModelInfo } from '../types';

interface SessionStripProps {
  systemStatus: SystemStatus | null;
  modelInfo: ModelInfo | null;
  activeFlows: number;
}

interface StatCellProps {
  label: string;
  value: string | number;
  danger?: boolean;
}

const StatCell: React.FC<StatCellProps> = ({ label, value, danger = false }) => (
  <div
    style={{
      padding: '6px 16px',
      borderRight: '1px solid rgba(255,255,255,0.14)',
      display: 'flex',
      flexDirection: 'column',
      gap: '2px',
      minWidth: '100px',
    }}
  >
    <div
      style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '8px',
        letterSpacing: '0.18em',
        textTransform: 'uppercase',
        color: 'rgba(255,255,255,0.42)',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </div>
    <div
      style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '13px',
        fontWeight: 400,
        letterSpacing: '0.08em',
        color: danger ? '#D14B32' : '#fff',
        whiteSpace: 'nowrap',
      }}
    >
      {value}
    </div>
  </div>
);

export const SessionStrip: React.FC<SessionStripProps> = ({ systemStatus, modelInfo, activeFlows }) => {
  const packetsProcessed = systemStatus?.packets_processed ?? '—';
  const windowsCompleted = systemStatus?.windows_completed ?? '—';
  const processingErrors = systemStatus?.processing_errors ?? 0;
  const detectionsGenerated = systemStatus?.detections_generated ?? '—';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'row',
        alignItems: 'stretch',
        background: 'rgba(255,255,255,0.03)',
        borderBottom: '1px solid rgba(255,255,255,0.14)',
        overflowX: 'auto',
        flexShrink: 0,
      }}
    >
      <StatCell
        label="Packets Processed"
        value={typeof packetsProcessed === 'number' ? packetsProcessed.toLocaleString() : packetsProcessed}
      />
      <StatCell
        label="Windows Completed"
        value={typeof windowsCompleted === 'number' ? windowsCompleted.toLocaleString() : windowsCompleted}
      />
      <StatCell
        label="Active Flows"
        value={activeFlows.toLocaleString()}
      />
      <StatCell
        label="Detections"
        value={typeof detectionsGenerated === 'number' ? detectionsGenerated.toLocaleString() : detectionsGenerated}
      />
      <StatCell
        label="Parse Errors"
        value={typeof processingErrors === 'number' ? processingErrors.toLocaleString() : processingErrors}
        danger={typeof processingErrors === 'number' && processingErrors > 0}
      />

      {/* Separator */}
      <div style={{ flex: 1 }} />

      {/* Model info — right-aligned */}
      {modelInfo && (
        <div
          style={{
            padding: '6px 16px',
            borderLeft: '1px solid rgba(255,255,255,0.14)',
            display: 'flex',
            flexDirection: 'column',
            gap: '2px',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <div
            style={{
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '8px',
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: 'rgba(255,255,255,0.42)',
            }}
          >
            ML Engine
          </div>
          <div
            style={{
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '10px',
              fontWeight: 400,
              letterSpacing: '0.08em',
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <span>{modelInfo.model_name}</span>
            <span
              style={{
                fontSize: '8px',
                border: '1px solid rgba(255,255,255,0.26)',
                padding: '1px 4px',
                color: 'rgba(255,255,255,0.62)',
                letterSpacing: '0.14em',
              }}
            >
              {modelInfo.features_expected}F
            </span>
          </div>
        </div>
      )}

      {/* NOTE: Protocol distribution (TCP/UDP %) is not available in the WebSocket
           metrics payload or state.py. Adding this would require backend changes
           which are out of scope. This stat is omitted. */}
    </div>
  );
};
