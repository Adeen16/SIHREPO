import React from 'react';
import type { Alert } from '../types';

interface WatchStationsProps {
  alerts: Alert[];
}

/**
 * VIGIL v2 — Watch Stations
 * Design decision: Converted from dial/needle gauges to flat horizontal bar meters.
 * Rationale: Flat bar meters are consistent with the sharp-rectangle, no-border-radius
 * design system. The gauge semicircle required bezier SVG arcs which introduced curved
 * elements that conflict with the design rules. Bar meters are also more legible
 * at the small height of the bottom strip.
 */

const DETECTORS = [
  { id: 'DDoS',            name: 'Traffic Flood',            isML: true  },
  { id: 'C2_BEACONING',    name: 'Beacon Pattern',           isML: false },
  { id: 'DNS_DGA_TUNNEL',  name: 'DNS Anomaly',              isML: false },
  { id: 'ENCRYPTED_MALWARE', name: 'Encrypted Sess.',        isML: false },
  { id: 'RECONNAISSANCE',  name: 'Network Scan',             isML: false },
  { id: 'DATA_EXFILTRATION', name: 'Data Departure',         isML: false },
] as const;

export const WatchStations: React.FC<WatchStationsProps> = ({ alerts }) => {
  const [now, setNow] = React.useState(Date.now() / 1000);

  React.useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, []);

  const getLevel = (threatId: string): number => {
    const recentAlerts = alerts.filter(a => {
      const timeRef = a.receivedAt || a.timestamp;
      return a.threat_class.toUpperCase().includes(threatId.toUpperCase()) &&
             (now - timeRef) < 15;
    });

    if (recentAlerts.length === 0) return 0;

    let maxSeverityLevel = 0;
    for (const a of recentAlerts) {
      let sl = 0;
      if (a.severity === 'CRITICAL') sl = 1.0;
      else if (a.severity === 'HIGH') sl = 0.8;
      else if (a.severity === 'MEDIUM') sl = 0.5;
      else if (a.severity === 'LOW') sl = 0.2;
      else sl = 0.1;
      if (sl > maxSeverityLevel) maxSeverityLevel = sl;
    }

    const latest = Math.max(...recentAlerts.map(a => a.receivedAt || a.timestamp));
    const age = now - latest;
    const decay = Math.max(0, 1 - age / 15);
    return maxSeverityLevel * decay;
  };

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(6, 1fr)',
        borderTop: '1px solid rgba(255,255,255,0.14)',
      }}
    >
      {DETECTORS.map((det, i) => {
        const level = getLevel(det.id);
        const isActive = level > 0;
        const pct = Math.round(level * 100);

        return (
          <div
            key={det.id}
            style={{
              borderRight: i < DETECTORS.length - 1 ? '1px solid rgba(255,255,255,0.14)' : 'none',
              padding: '10px 12px',
              background: isActive ? 'rgba(209,75,50,0.04)' : 'transparent',
              transition: 'background 0.25s',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            {/* Label row */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span
                style={{
                  fontFamily: 'Sora, sans-serif',
                  fontSize: '10px',
                  fontWeight: 300,
                  color: isActive ? '#fff' : 'rgba(255,255,255,0.42)',
                  transition: 'color 0.25s',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  maxWidth: '80%',
                }}
              >
                {det.name}
              </span>
              <span
                style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '7px',
                  letterSpacing: '0.14em',
                  textTransform: 'uppercase',
                  border: '1px solid rgba(255,255,255,0.14)',
                  padding: '1px 3px',
                  color: det.isML ? 'rgba(255,255,255,0.62)' : 'rgba(255,255,255,0.28)',
                  flexShrink: 0,
                }}
              >
                {det.isML ? 'ML' : 'BEH'}
              </span>
            </div>

            {/* Flat bar meter */}
            <div
              style={{
                height: '3px',
                background: 'rgba(255,255,255,0.08)',
                position: 'relative',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  height: '100%',
                  width: `${pct}%`,
                  background: '#D14B32',
                  transition: 'width 0.5s cubic-bezier(0.16,1,0.3,1)',
                }}
              />
            </div>

            {/* Status readout */}
            <div
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '10px',
                fontWeight: 400,
                letterSpacing: '0.1em',
                color: isActive ? '#D14B32' : 'rgba(255,255,255,0.28)',
                transition: 'color 0.25s',
              }}
            >
              {isActive ? `${pct}%` : 'QUIET'}
            </div>

          </div>
        );
      })}
    </div>
  );
};
