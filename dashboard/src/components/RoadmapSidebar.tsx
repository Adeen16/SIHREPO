import React, { useState } from 'react';

const ROADMAP_ITEMS = [
  {
    id: 'ps153',
    name: 'PS153 Predictive',
    desc: 'Forecasts attack probability in the next 5-min window using temporal ML over flow telemetry.',
  },
  {
    id: 'mitre',
    name: 'MITRE ATT&CK',
    desc: 'Maps live detections to ATT&CK technique IDs and reconstructs multi-stage attack narratives.',
  },
  {
    id: 'dna',
    name: 'Threat DNA',
    desc: 'Tracks drift in threat fingerprints across sessions to identify evolving adversary TTPs.',
  },
  {
    id: 'cf',
    name: 'Counterfactual',
    desc: 'Answers "what if this flow had a different port/volume?" to stress-test detection boundaries.',
  },
  {
    id: 'blast',
    name: 'Blast Radius',
    desc: 'Estimates the number of hosts reachable from an infected pivot given current network topology.',
  },
  {
    id: 'poison',
    name: 'Baseline Defense',
    desc: 'Detects adversarial attempts to slowly shift the feature baseline and evade anomaly detection.',
  },
  {
    id: 'timemachine',
    name: 'Time Machine',
    desc: 'Re-plays historical PCAP segments with updated models to surface retrospectively-detected threats.',
  },
];

export const RoadmapSidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <aside
      style={{
        width: collapsed ? '28px' : '200px',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        borderRight: '1px solid rgba(255,255,255,0.14)',
        transition: 'width 0.3s cubic-bezier(0.16,1,0.3,1)',
        overflow: 'hidden',
        opacity: 0.5, // Desaturated — "not yet operational"
      }}
    >
      {/* Toggle strip */}
      <button
        onClick={() => setCollapsed(c => !c)}
        aria-label={collapsed ? 'Expand roadmap' : 'Collapse roadmap'}
        style={{
          flexShrink: 0,
          height: '28px',
          width: '100%',
          background: 'transparent',
          border: 'none',
          borderBottom: '1px solid rgba(255,255,255,0.14)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'rgba(255,255,255,0.28)',
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '9px',
          letterSpacing: '0.14em',
          transition: 'color 0.2s',
        }}
        onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.62)')}
        onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.28)')}
      >
        {collapsed ? '▶' : '◀'}
      </button>

      {!collapsed && (
        <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', flex: 1, minHeight: 0 }}>
          {/* Header */}
          <div
            style={{
              padding: '8px 10px',
              borderBottom: '1px solid rgba(255,255,255,0.14)',
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
                lineHeight: 1.4,
              }}
            >
              ROADMAP
            </div>
            <div
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '8px',
                letterSpacing: '0.14em',
                textTransform: 'uppercase',
                color: '#D14B32',
                opacity: 0.7,
                lineHeight: 1.4,
              }}
            >
              NOT OPERATIONAL
            </div>
          </div>

          {/* Items */}
          <ul
            style={{
              flex: 1,
              overflowY: 'auto',
              listStyle: 'none',
              margin: 0,
              padding: 0,
            }}
          >
            {ROADMAP_ITEMS.map(item => (
              <li
                key={item.id}
                style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                <button
                  onClick={() => setExpanded(e => e === item.id ? null : item.id)}
                  style={{
                    width: '100%',
                    textAlign: 'left',
                    background: 'transparent',
                    border: 'none',
                    padding: '7px 10px',
                    cursor: 'pointer',
                    color: 'rgba(255,255,255,0.42)',
                    fontFamily: 'Sora, sans-serif',
                    fontSize: '10px',
                    fontWeight: 300,
                    lineHeight: 1.3,
                    transition: 'color 0.2s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.62)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.42)')}
                >
                  {item.name}
                </button>
                {expanded === item.id && (
                  <div
                    style={{
                      padding: '0 10px 8px',
                      fontFamily: 'Sora, sans-serif',
                      fontSize: '9px',
                      fontWeight: 200,
                      color: 'rgba(255,255,255,0.28)',
                      lineHeight: 1.5,
                    }}
                  >
                    {item.desc}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </aside>
  );
};
