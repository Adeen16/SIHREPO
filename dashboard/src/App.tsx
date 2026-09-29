import React, { useEffect, useState, useRef } from 'react';
import { format } from 'date-fns';
import { Waterfall } from './components/Waterfall';
import { ContactLog } from './components/ContactLog';
import { BearingBoard } from './components/BearingBoard';
import { WatchStations } from './components/WatchStations';
import type { Alert, WindowMetrics, FlowHost } from './types';


export interface DashboardState {
  metrics: WindowMetrics | null;
  alerts: Alert[];
  hosts: FlowHost[];
  uptime: number; // seconds
}

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isStarted, setIsStarted] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  // Pipeline-level error broadcast from backend (e.g. corrupt PCAP)
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [state, setState] = useState<DashboardState>({
    metrics: null,
    alerts: [],
    hosts: [],
    uptime: 0
  });

  const wsRef = useRef<WebSocket | null>(null);
  const startTime = useRef(Date.now());

  useEffect(() => {
    if (!isStarted) return;

    // Timer for uptime
    const timer = setInterval(() => {
      setState(s => ({ ...s, uptime: Math.floor((Date.now() - startTime.current) / 1000) }));
    }, 1000);

    // Connect to WebSocket
    const connect = () => {
      const ws = new WebSocket('ws://127.0.0.1:8000/ws');
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'alert') {
            const newAlert = { ...data.payload, receivedAt: Date.now() / 1000 };
            setState(s => ({
              ...s,
              alerts: [newAlert, ...s.alerts].slice(0, 1000) // Keep last 1000
            }));
          } else if (data.type === 'metrics') {
            setState(s => ({
              ...s,
              metrics: data.payload
            }));
          } else if (data.type === 'hosts') {
            setState(s => ({
              ...s,
              hosts: data.payload
            }));
          } else if (data.type === 'reset') {
            setState({
              metrics: null,
              alerts: [],
              hosts: [],
              uptime: 0
            });
            setUploadError(null); // Clear any previous error on fresh run
            startTime.current = Date.now();
          } else if (data.type === 'error') {
            setUploadError(data.payload?.message || 'Unknown pipeline error');
          }
        } catch (e) {
          console.error("Failed to parse websocket message", e);
        }
      };

      ws.onclose = () => {
        // Option to reconnect or just stop
        console.log("WebSocket closed");
      };
    };

    connect();

    return () => {
      clearInterval(timer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [isStarted]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    } else {
      setSelectedFile(null);
    }
  };

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg("Please select a PCAP file to upload.");
      return;
    }
    setErrorMsg(null);
    setIsUploading(true);
    
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const res = await fetch('http://127.0.0.1:8000/demo/upload_pcap', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) {
        const d = await res.json();
        setErrorMsg(d.detail || "Error starting pipeline");
        setIsUploading(false);
        return;
      }
      startTime.current = Date.now();
      setIsStarted(true);
      setIsUploading(false);
    } catch (err: any) {
      setErrorMsg(err.message || "Network error");
      setIsUploading(false);
    }
  };

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  if (!isStarted) {
    return (
      <div className="min-h-screen bg-bg-base text-text-paper flex items-center justify-center p-4">
        <div className="w-full max-w-lg bg-bg-panel border border-grid-line p-8">
          <h1 className="font-display text-4xl uppercase tracking-wider text-text-paper mb-6 leading-none border-b border-grid-line pb-4">
            Listening&middot;Post
          </h1>
          <form onSubmit={handleStart} className="flex flex-col gap-6">
            <div className="flex flex-col gap-2">
              <label className="font-mono text-sm uppercase tracking-widest text-accent-cyan">
                UPLOAD PCAP SOURCE
              </label>
              <input
                type="file"
                accept=".pcap"
                onChange={handleFileChange}
                className="bg-[#12130F] border border-grid-line text-text-paper p-3 font-mono text-sm outline-none focus:border-accent-amber transition-colors file:mr-4 file:py-2 file:px-4 file:border-0 file:text-sm file:font-semibold file:bg-accent-cyan file:text-bg-base hover:file:bg-opacity-90"
              />
            </div>
            {errorMsg && (
              <div className="text-accent-red font-mono text-xs p-3 bg-accent-red/10 border border-accent-red">
                {errorMsg}
              </div>
            )}
            <button 
              type="submit" 
              disabled={isUploading}
              className={`mt-4 bg-accent-amber text-[#12130F] font-mono font-semibold uppercase tracking-widest py-3 transition-opacity ${isUploading ? 'opacity-50 cursor-not-allowed' : 'hover:bg-opacity-90'}`}
            >
              {isUploading ? 'UPLOADING...' : 'INITIALIZE PIPELINE'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg-base text-text-paper p-4 md:p-6 lg:p-8 flex flex-col h-screen overflow-hidden">
      {/* HEADER */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 border-b border-grid-line pb-4 shrink-0 gap-4">
        <h1 className="font-display text-4xl uppercase tracking-wider text-text-paper m-0 leading-none">
          Listening&middot;Post
        </h1>
        <div className="flex flex-wrap md:flex-nowrap gap-4 md:gap-6 font-mono text-sm uppercase tracking-widest text-accent-cyan">
          <div className="flex items-center gap-2">
            <span className="text-grid-line">MODE:</span> 
            <strong className="text-accent-amber font-semibold">PASSIVE / READ-ONLY</strong>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-grid-line">THROUGHPUT:</span> 
            <span>{state.metrics ? state.metrics.packets_per_second.toLocaleString() : '0'} pkt/s</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-grid-line">UPTIME:</span> 
            <span>{formatUptime(state.uptime)}</span>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col lg:flex-row gap-6 min-h-0">
        
        <div className="flex-1 flex flex-col gap-6 min-w-0">
          {/* WATERFALL (Top Left) */}
          <section className="flex-1 border border-grid-line bg-bg-panel flex flex-col overflow-hidden">
            <div className="border-b border-grid-line px-4 py-2 font-mono text-xs uppercase text-accent-cyan tracking-widest flex justify-between">
              <span>Traffic Waterfall &mdash; last 10s windows</span>
              <span className="text-grid-line">SLIDE 2s</span>
            </div>
            <div className="flex-1 relative overflow-hidden">
              <Waterfall currentMetrics={state.metrics} />
            </div>
          </section>

          {/* BEARING BOARD (Bottom Left) */}
          <section className="h-1/3 min-h-[250px] border border-grid-line bg-bg-panel flex flex-col shrink-0">
             <div className="border-b border-grid-line px-4 py-2 font-mono text-xs uppercase text-accent-cyan tracking-widest flex justify-between">
              <span>Bearing Board &mdash; communication graph</span>
              <span className="text-grid-line">{state.hosts.length} HOSTS</span>
            </div>
            <div className="flex-1 relative">
               <BearingBoard hosts={state.hosts} alerts={state.alerts} />
            </div>
          </section>
        </div>

        {/* CONTACT LOG (Right Rail) */}
        <section className={`w-full lg:w-96 border bg-bg-panel flex flex-col shrink-0 ${uploadError ? 'border-accent-red' : 'border-grid-line'}`}>
          <div className={`border-b px-4 py-2 font-mono text-xs uppercase tracking-widest flex justify-between shrink-0 ${uploadError ? 'border-accent-red text-accent-red' : 'border-grid-line text-accent-cyan'}`}>
            <span>Contact Log</span>
            <span className="text-grid-line">{state.alerts.length} LOGGED</span>
          </div>
          <div className="flex-1 overflow-y-auto min-h-0">
            <ContactLog alerts={state.alerts} uploadError={uploadError} />
          </div>
        </section>

      </div>

      {/* WATCH STATIONS (Bottom Strip) */}
      <section className="mt-6 border-t border-grid-line pt-6 shrink-0">
        <WatchStations alerts={state.alerts} />
      </section>

    </div>
  );
}

export default App;
