import React, { useState } from 'react';

const ROADMAP_ITEMS = [
  {
    id: 'ps153',
    name: 'PS153 Predictive Engine',
    desc: 'Forecasts attack probability in the next 5-minute window using temporal ML over flow telemetry.',
  },
  {
    id: 'mitre',
    name: 'MITRE ATT&CK Storyline',
    desc: 'Maps live detections to ATT&CK technique IDs and reconstructs multi-stage attack narratives.',
  },
  {
    id: 'dna',
    name: 'Threat DNA Evolution',
    desc: 'Tracks drift in threat fingerprints across sessions to identify evolving adversary TTPs.',
  },
  {
    id: 'cf',
    name: 'Counterfactual Simulation',
    desc: 'Answers "what if this flow had a different port/volume?" to stress-test detection boundaries.',
  },
  {
    id: 'blast',
    name: 'Blast-Radius Forecasting',
    desc: 'Estimates the number of hosts reachable from an infected pivot given current network topology.',
  },
  {
    id: 'poison',
    name: 'Baseline Poisoning Defense',
    desc: 'Detects adversarial attempts to slowly shift the feature baseline and evade anomaly detection.',
  },
  {
    id: 'timemachine',
    name: 'Time Machine Replay',
    desc: 'Re-plays historical PCAP segments with updated models to surface retrospectively-detected threats.',
  },
];

export const RoadmapSidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <aside
      className={`
        shrink-0 flex flex-col border-r border-grid-line bg-bg-panel
        transition-all duration-300 ease-in-out overflow-hidden
        ${collapsed ? 'w-8' : 'w-64'}
      `}
      style={{ filter: 'saturate(0.35) brightness(0.7)' }}
    >
      {/* Toggle strip */}
      <button
        onClick={() => setCollapsed(c => !c)}
        className="shrink-0 flex items-center justify-center h-8 w-full border-b border-grid-line hover:brightness-125 transition-all"
        title={collapsed ? 'Expand roadmap' : 'Collapse roadmap'}
        aria-label="Toggle roadmap sidebar"
      >
        <span className="font-mono text-[9px] text-grid-line uppercase tracking-widest">
          {collapsed ? '▶' : '◀'}
        </span>
      </button>

      {!collapsed && (
        <div className="flex flex-col overflow-hidden flex-1 min-h-0">
          {/* Header */}
          <div className="px-3 py-2 border-b border-grid-line shrink-0">
            <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-grid-line block leading-tight">
              ROADMAP
            </span>
            <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-accent-red/60 block leading-tight">
              NOT YET OPERATIONAL
            </span>
          </div>

          {/* Items */}
          <ul className="flex-1 overflow-y-auto list-none m-0 p-0">
            {ROADMAP_ITEMS.map(item => (
              <li key={item.id} className="border-b border-grid-line">
                <button
                  className="w-full text-left px-3 py-2 hover:bg-[#1a1d17] transition-colors"
                  onClick={() => setExpanded(e => e === item.id ? null : item.id)}
                >
                  <span className="font-mono text-[10px] text-text-paper/60 uppercase tracking-wider block leading-snug">
                    {item.name}
                  </span>
                </button>
                {expanded === item.id && (
                  <div className="px-3 pb-2 font-mono text-[9px] text-grid-line leading-relaxed">
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
