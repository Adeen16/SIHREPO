import React from 'react';
import type { Alert } from '../types';

interface WatchStationsProps {
  alerts: Alert[];
}

// Map internal classes to display names and type
const DETECTORS = [
  { id: 'DDoS', name: 'Traffic Flood', isML: true },
  { id: 'C2_BEACONING', name: 'Beacon Pattern', isML: false },
  { id: 'DNS_DGA_TUNNEL', name: 'DNS Anomaly', isML: false },
  { id: 'ENCRYPTED_MALWARE', name: 'Encrypted Session Anomaly', isML: false },
  { id: 'RECONNAISSANCE', name: 'Network Scan', isML: false },
  { id: 'DATA_EXFILTRATION', name: 'Data Departure', isML: false },
];

export const WatchStations: React.FC<WatchStationsProps> = ({ alerts }) => {
  // Use React state and interval to trigger re-renders for the decay animation
  const [now, setNow] = React.useState(Date.now() / 1000);

  React.useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now() / 1000);
    }, 1000);
    return () => clearInterval(timer);
  }, []);
  
  const getDetectorActivity = (threatId: string) => {
    // Find alerts for this class in the last 15 seconds of real wall clock time
    const recentAlerts = alerts.filter(a => {
      const timeRef = a.receivedAt || a.timestamp;
      return a.threat_class.toUpperCase().includes(threatId.toUpperCase()) && 
             (now - timeRef) < 15;
    });
    
    // Scale 0 to 1 based on severity
    let maxSeverityLevel = 0;
    for (const a of recentAlerts) {
      let sl = 0;
      if (a.severity === 'CRITICAL') sl = 1.0;
      else if (a.severity === 'HIGH') sl = 0.8;
      else if (a.severity === 'MEDIUM') sl = 0.5;
      else if (a.severity === 'LOW') sl = 0.2;
      else sl = 0.1; // unknown
      if (sl > maxSeverityLevel) maxSeverityLevel = sl;
    }
    
    // Add small decay based on time since last alert for smooth animation down
    if (recentAlerts.length > 0) {
       const latest = Math.max(...recentAlerts.map(a => a.receivedAt || a.timestamp));
       const age = now - latest;
       // Decay linearly from maxSeverityLevel to 0 over 15 seconds
       const decay = Math.max(0, 1 - (age / 15));
       return maxSeverityLevel * decay;
    }
    return 0;
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {DETECTORS.map(det => {
        const level = getDetectorActivity(det.id);
        const isActive = level > 0;
        
        // Needle rotation: -45deg (min) to +45deg (max)
        const rotation = -45 + (level * 90);

        return (
          <div 
            key={det.id} 
            className={`border transition-all duration-300 p-3 flex flex-col justify-between relative overflow-hidden ${isActive ? 'bg-accent-red/5 border-accent-red/30' : 'bg-bg-panel border-grid-line hover:border-[#3A3D37]'}`}
          >
            <div className="flex justify-between items-start mb-4 relative z-10">
              <span className="font-mono text-[10px] uppercase text-text-paper tracking-[0.1em] leading-tight max-w-[70%]">
                {det.name}
              </span>
              <span className={`font-mono text-[9px] px-1 rounded-sm ${det.isML ? 'bg-accent-cyan/20 text-accent-cyan' : 'bg-[#2B2E29] text-grid-line'}`}>
                {det.isML ? 'ML' : 'BEH'}
              </span>
            </div>
            
            <div className="relative h-12 flex items-end justify-center mb-1">
              {/* Gauge Arc */}
              <svg className="absolute w-20 h-10 bottom-0" viewBox="0 0 100 50">
                {/* Background Track */}
                <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="#2B2E29" strokeWidth="4" strokeLinecap="square" />
                {/* Active Track */}
                {isActive && (
                  <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="#C4432B" strokeWidth="4" strokeLinecap="square" 
                    strokeDasharray="125" 
                    strokeDashoffset={125 - (125 * level)} 
                    style={{ transition: 'stroke-dashoffset 0.5s ease' }} 
                  />
                )}
              </svg>
              
              {/* Needle Pivot */}
              <div className="absolute w-3 h-3 bg-grid-line rounded-full bottom-[-6px]" />
              
              {/* Needle */}
              <div 
                className="absolute bottom-0 w-1 h-12 bg-accent-amber origin-bottom transition-transform duration-300 ease-out"
                style={{ transform: `rotate(${rotation}deg)` }}
              />
            </div>
            
            <div className="text-center font-mono text-xs mt-2 relative z-10 font-medium">
              <span className={isActive ? 'text-accent-red' : 'text-accent-cyan opacity-50'}>
                {isActive ? `${(level * 100).toFixed(0)}%` : 'QUIET'}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
