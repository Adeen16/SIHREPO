import React, { useState } from 'react';
import { format } from 'date-fns';
import type { Alert } from '../types';

interface ContactLogProps {
  alerts: Alert[];
}

export const ContactLog: React.FC<ContactLogProps> = ({ alerts }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (alerts.length === 0) {
    return (
      <div className="h-full flex items-center justify-center p-4">
        <span className="font-mono text-sm text-grid-line uppercase tracking-widest">
          No contacts logged.
        </span>
      </div>
    );
  }

  const toggleExpand = (id: string) => {
    setExpandedId(prev => prev === id ? null : id);
  };

  return (
    <ul className="m-0 p-0 list-none">
      {alerts.map((alert, idx) => {
        // Unique ID for UI purposes since flow_id might have multiple alerts over time
        const uiId = `${alert.flow_id}-${alert.timestamp}-${idx}`;
        const isExpanded = expandedId === uiId;
        const isHighSeverity = alert.severity === 'HIGH' || alert.confidence >= 0.9;
        
        return (
          <li 
            key={uiId}
            className={`
              border-b border-grid-line cursor-pointer hover:bg-[#20221C] transition-colors
              ${isHighSeverity ? 'border-l-2 border-l-accent-red' : 'border-l-2 border-l-transparent'}
            `}
            onClick={() => toggleExpand(uiId)}
          >
            <div className="p-3 font-mono text-xs text-text-paper flex flex-col gap-1">
              <div className="flex gap-3 overflow-hidden">
                <span className="text-accent-cyan whitespace-nowrap shrink-0">
                  {format(new Date(alert.timestamp * 1000), 'HH:mm:ss.SSS')}
                </span>
                <span className="truncate min-w-0 opacity-80" title={alert.flow_id}>
                  {alert.flow_id}
                </span>
              </div>
              <div className="flex gap-3 items-center overflow-hidden">
                <span className={`truncate min-w-0 ${isHighSeverity ? 'text-accent-red font-semibold' : 'text-accent-amber'}`} title={alert.threat_class}>
                  {alert.threat_class}
                </span>
                <span className="opacity-50 whitespace-nowrap shrink-0">
                  CONF: {(alert.confidence * 100).toFixed(0)}%
                </span>
              </div>
            </div>
            
            {isExpanded && (
              <div className="px-3 pb-3 pt-1 text-xs font-mono text-text-paper opacity-70 bg-[#161814]">
                <div className="mb-1 text-grid-line uppercase">Evidence:</div>
                {alert.evidence?.reason ? (
                  <div>{alert.evidence.reason}</div>
                ) : (
                  <pre className="m-0 bg-transparent text-xs whitespace-pre-wrap font-inherit">
                    {JSON.stringify(alert.evidence, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
};
