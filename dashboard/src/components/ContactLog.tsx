import React, { useState } from 'react';
import { format } from 'date-fns';
import type { Alert } from '../types';

interface ContactLogProps {
  alerts: Alert[];
  uploadError: string | null;
}

const STATUS_COLOR: Record<string, string> = {
  DETECTED: 'text-accent-red',
  UNVALIDATED: 'text-accent-amber',
  NOT_DETECTED: 'text-grid-line',
  INSUFFICIENT_DATA: 'text-grid-line',
  BENIGN: 'text-accent-cyan',
  error: 'text-accent-red/50',
};

const STATUS_LABEL: Record<string, string> = {
  DETECTED: 'DETECT',
  UNVALIDATED: 'UNVAL.',
  NOT_DETECTED: 'CLEAR',
  INSUFFICIENT_DATA: 'INSUF.',
  BENIGN: 'BENIGN',
  error: 'ERROR',
};

export const ContactLog: React.FC<ContactLogProps> = ({ alerts, uploadError }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Show pipeline error state — distinct from "no threats found"
  if (uploadError) {
    return (
      <div className="h-full flex flex-col items-start justify-start p-4 gap-3">
        <div className="w-full bg-accent-red/10 border border-accent-red p-4 font-mono">
          <div className="text-accent-red text-xs uppercase tracking-widest font-semibold mb-2">
            ⚠ UPLOAD FAILED
          </div>
          <div className="text-accent-red text-xs break-words">{uploadError}</div>
        </div>
        <p className="font-mono text-xs text-grid-line">
          The file could not be processed. Please upload a valid .pcap capture file.
        </p>
      </div>
    );
  }

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
            {/* Summary row */}
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

            {/* Expanded evidence panel */}
            {isExpanded && (
              <div className="px-3 pb-3 pt-1 text-xs font-mono text-text-paper bg-[#161814] border-t border-grid-line">

                {/* 1. Winning evidence */}
                <div className="mb-2">
                  <div className="text-[9px] text-grid-line uppercase tracking-widest mb-1">Evidence</div>
                  {alert.evidence?.reason ? (
                    <div className="text-text-paper/80">{alert.evidence.reason}</div>
                  ) : (
                    <pre className="m-0 bg-transparent text-xs whitespace-pre-wrap font-inherit text-text-paper/70">
                      {JSON.stringify(alert.evidence, null, 2)}
                    </pre>
                  )}
                </div>

                {/* 2. Fusion reason */}
                {alert.fusion_reason && (
                  <div className="mb-3 px-2 py-1 border border-accent-amber/30 bg-accent-amber/5">
                    <span className="text-[9px] text-grid-line uppercase tracking-widest">Fusion decision: </span>
                    <span className="text-accent-amber">{alert.fusion_reason}</span>
                  </div>
                )}

                {/* 3. Six-detector breakdown */}
                {alert.all_detector_results && alert.all_detector_results.length > 0 && (
                  <div>
                    <div className="text-[9px] text-grid-line uppercase tracking-widest mb-1">Detector Breakdown</div>
                    <table className="w-full border-collapse">
                      <thead>
                        <tr className="text-[8px] text-grid-line uppercase">
                          <th className="text-left pb-1 pr-2 font-normal">Detector</th>
                          <th className="text-left pb-1 pr-2 font-normal">Status</th>
                          <th className="text-right pb-1 font-normal">Conf.</th>
                        </tr>
                      </thead>
                      <tbody>
                        {alert.all_detector_results.map((dr, i) => (
                          <tr key={i} className="border-t border-grid-line/30">
                            <td className="py-0.5 pr-2 text-text-paper/70 text-[9px] whitespace-nowrap">
                              {dr.detector}
                            </td>
                            <td className={`py-0.5 pr-2 text-[9px] ${STATUS_COLOR[dr.status] ?? 'text-text-paper'}`}>
                              {STATUS_LABEL[dr.status] ?? dr.status}
                            </td>
                            <td className="py-0.5 text-right text-[9px] text-text-paper/60">
                              {dr.confidence != null ? `${(dr.confidence * 100).toFixed(0)}%` : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
};
