import React, { useEffect, useState, useRef, useCallback } from 'react';
import './App.css';
import { Waterfall } from './components/Waterfall';
import { ContactLog } from './components/ContactLog';
import { BearingBoard } from './components/BearingBoard';
import { WatchStations } from './components/WatchStations';
import { RoadmapSidebar } from './components/RoadmapSidebar';
import { SessionStrip } from './components/SessionStrip';
import type { Alert, WindowMetrics, FlowHost, SystemStatus, ModelInfo } from './types';

export interface DashboardState {
  metrics: WindowMetrics | null;
  alerts: Alert[];
  hosts: FlowHost[];
  uptime: number;
}

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isStarted, setIsStarted] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [state, setState] = useState<DashboardState>({
    metrics: null,
    alerts: [],
    hosts: [],
    uptime: 0
  });

  // Session stats polled from GET /status
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  // Model info polled from GET /model
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const startTime = useRef(Date.now());
  const statusPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch model info once on mount
  useEffect(() => {
    fetch('http://127.0.0.1:8000/model')
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setModelInfo(data); })
      .catch(() => {});
  }, []);

  // Poll /status every 2s while running
  const startStatusPoll = useCallback(() => {
    if (statusPollRef.current) clearInterval(statusPollRef.current);
    statusPollRef.current = setInterval(() => {
      fetch('http://127.0.0.1:8000/status')
        .then(r => r.ok ? r.json() : null)
        .then(data => { if (data) setSystemStatus(data); })
        .catch(() => {});
    }, 2000);
  }, []);

  const stopStatusPoll = useCallback(() => {
    if (statusPollRef.current) {
      clearInterval(statusPollRef.current);
      statusPollRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!isStarted) return;

    // Uptime ticker
    const timer = setInterval(() => {
      setState(s => ({ ...s, uptime: Math.floor((Date.now() - startTime.current) / 1000) }));
    }, 1000);

    startStatusPoll();

    // WebSocket connection
    const ws = new WebSocket('ws://127.0.0.1:8000/ws');
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'alert') {
          const newAlert = { ...data.payload, receivedAt: Date.now() / 1000 };
          setState(s => ({
            ...s,
            alerts: [newAlert, ...s.alerts].slice(0, 1000)
          }));
        } else if (data.type === 'metrics') {
          setState(s => ({ ...s, metrics: data.payload }));
        } else if (data.type === 'hosts') {
          setState(s => ({ ...s, hosts: data.payload }));
        } else if (data.type === 'reset') {
          setState({ metrics: null, alerts: [], hosts: [], uptime: 0 });
          setUploadError(null);
          startTime.current = Date.now();
        } else if (data.type === 'error') {
          setUploadError(data.payload?.message || 'Unknown pipeline error');
        }
      } catch (e) {
        console.error('Failed to parse websocket message', e);
      }
    };

    ws.onclose = () => console.log('WebSocket closed');

    return () => {
      clearInterval(timer);
      stopStatusPoll();
      ws.close();
    };
  }, [isStarted, startStatusPoll, stopStatusPoll]);

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
      setErrorMsg('Select a PCAP file to upload.');
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
        setErrorMsg(d.detail || 'Error starting pipeline');
        setIsUploading(false);
        return;
      }
      startTime.current = Date.now();
      setIsStarted(true);
      setIsUploading(false);
    } catch (err: any) {
      setErrorMsg(err.message || 'Network error');
      setIsUploading(false);
    }
  };

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;
  };

  // ─── UPLOAD SCREEN ────────────────────────────────────────────────────────
  if (!isStarted) {
    return (
      <div
        style={{ background: '#000', minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}
      >
        <div
          style={{
            width: '100%',
            maxWidth: '440px',
            border: '1px solid rgba(255,255,255,0.14)',
            padding: '40px 36px',
          }}
        >
          {/* Brand */}
          <div style={{ marginBottom: '32px' }}>
            <div className="brand" style={{ fontSize: '32px', color: '#fff', lineHeight: 1 }}>
              VIGIL
            </div>
            <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.42)', marginTop: '6px' }}>
              Passive Threat Intelligence · NTRO SIH-145
            </div>
          </div>

          {/* Divider */}
          <div style={{ height: '1px', background: 'rgba(255,255,255,0.14)', marginBottom: '28px' }} />

          <form onSubmit={handleStart}>
            <div style={{ marginBottom: '20px' }}>
              <label className="readout" style={{ display: 'block', fontSize: '9px', color: 'rgba(255,255,255,0.42)', marginBottom: '8px' }}>
                PCAP Source File
              </label>
              <input
                id="pcap-file-input"
                type="file"
                accept=".pcap"
                onChange={handleFileChange}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.14)',
                  color: '#fff',
                  padding: '10px 12px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '12px',
                  letterSpacing: '0.08em',
                  cursor: 'pointer',
                }}
              />
            </div>

            {errorMsg && (
              <div
                style={{
                  border: '1px solid #D14B32',
                  background: 'rgba(209,75,50,0.08)',
                  padding: '10px 12px',
                  marginBottom: '16px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '11px',
                  color: '#D14B32',
                  letterSpacing: '0.08em',
                }}
              >
                {errorMsg}
              </div>
            )}

            <button
              id="initialize-pipeline-btn"
              type="submit"
              disabled={isUploading}
              style={{
                width: '100%',
                padding: '12px',
                background: isUploading ? 'rgba(209,75,50,0.15)' : '#D14B32',
                border: isUploading ? '1px solid #D14B32' : '1px solid #D14B32',
                color: isUploading ? '#D14B32' : '#000',
                fontFamily: 'JetBrains Mono, monospace',
                fontWeight: 500,
                fontSize: '11px',
                letterSpacing: '0.22em',
                textTransform: 'uppercase',
                cursor: isUploading ? 'not-allowed' : 'pointer',
                transition: 'background 0.2s, color 0.2s',
              }}
            >
              {isUploading ? 'PROCESSING...' : 'INITIALIZE PIPELINE'}
            </button>
          </form>

          {/* Footer note */}
          <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid rgba(255,255,255,0.14)' }}>
            <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.28)', lineHeight: 1.6 }}>
              READ-ONLY · NO PACKETS TRANSMITTED<br />
              PASSIVE INGESTION PIPELINE
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── MAIN DASHBOARD ───────────────────────────────────────────────────────
  return (
    <div style={{ background: '#000', height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── HEADER ── */}
      <header
        style={{
          borderBottom: '1px solid rgba(255,255,255,0.14)',
          padding: '10px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexShrink: 0,
          gap: '16px',
          flexWrap: 'wrap',
        }}
      >
        {/* Brand */}
        <div className="brand" style={{ fontSize: '20px', color: '#fff', letterSpacing: '0.26em' }}>
          VIGIL
        </div>

        {/* Live metrics strip */}
        <div style={{ display: 'flex', gap: '28px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.42)' }}>
            <span style={{ marginRight: '6px' }}>MODE</span>
            <span style={{ color: '#fff' }}>PASSIVE / READ-ONLY</span>
          </div>
          <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.42)' }}>
            <span style={{ marginRight: '6px' }}>THROUGHPUT</span>
            <span style={{ color: '#fff' }}>
              {state.metrics ? Math.round(state.metrics.packets_per_second).toLocaleString() : '0'} PKT/S
            </span>
          </div>
          <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.42)' }}>
            <span style={{ marginRight: '6px' }}>UPTIME</span>
            <span style={{ color: '#fff' }}>{formatUptime(state.uptime)}</span>
          </div>
          <div className="readout" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.42)' }}>
            <span style={{ marginRight: '6px' }}>ALERTS</span>
            <span style={{ color: state.alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length > 0 ? '#D14B32' : '#fff' }}>
              {state.alerts.length}
            </span>
          </div>
        </div>
      </header>

      {/* ── SESSION STATS STRIP ── */}
      <SessionStrip
        systemStatus={systemStatus}
        modelInfo={modelInfo}
        activeFlows={state.metrics?.active_flows ?? 0}
      />

      {/* ── MAIN CONTENT AREA ── */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>

        {/* Roadmap sidebar */}
        <RoadmapSidebar />

        {/* Center + Right content */}
        <div style={{ flex: 1, display: 'flex', minWidth: 0, minHeight: 0 }}>

          {/* Left column: Waterfall + Bearing Board */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, borderRight: '1px solid rgba(255,255,255,0.14)' }}>

            {/* Waterfall panel */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, borderBottom: '1px solid rgba(255,255,255,0.14)' }}>
              <div
                className="readout"
                style={{
                  fontSize: '9px',
                  color: 'rgba(255,255,255,0.42)',
                  padding: '6px 12px',
                  borderBottom: '1px solid rgba(255,255,255,0.14)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  flexShrink: 0,
                }}
              >
                <span>TRAFFIC WATERFALL — PACKETS/SEC</span>
                <span>WINDOW 10S · SLIDE 1S</span>
              </div>
              <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
                <Waterfall currentMetrics={state.metrics} />
              </div>
            </div>

            {/* Bearing Board panel */}
            <div style={{ height: '40%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
              <div
                className="readout"
                style={{
                  fontSize: '9px',
                  color: 'rgba(255,255,255,0.42)',
                  padding: '6px 12px',
                  borderBottom: '1px solid rgba(255,255,255,0.14)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  flexShrink: 0,
                }}
              >
                <span>HOST GRID — COMMUNICATION MAP</span>
                <span>{state.hosts.length} ACTIVE HOSTS</span>
              </div>
              <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
                <BearingBoard hosts={state.hosts} alerts={state.alerts} />
              </div>
            </div>

          </div>

          {/* Right column: Contact Log */}
          <div
            style={{
              width: '380px',
              flexShrink: 0,
              display: 'flex',
              flexDirection: 'column',
              borderLeft: uploadError ? '1px solid #D14B32' : '1px solid rgba(255,255,255,0.14)',
            }}
          >
            <div
              className="readout"
              style={{
                fontSize: '9px',
                color: uploadError ? '#D14B32' : 'rgba(255,255,255,0.42)',
                padding: '6px 12px',
                borderBottom: uploadError ? '1px solid #D14B32' : '1px solid rgba(255,255,255,0.14)',
                display: 'flex',
                justifyContent: 'space-between',
                flexShrink: 0,
              }}
            >
              <span>CONTACT LOG — THREAT EVENTS</span>
              <span>{state.alerts.length} LOGGED</span>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
              <ContactLog alerts={state.alerts} uploadError={uploadError} modelInfo={modelInfo} />
            </div>
          </div>

        </div>
      </div>

      {/* ── WATCH STATIONS STRIP ── */}
      <div style={{ borderTop: '1px solid rgba(255,255,255,0.14)', flexShrink: 0 }}>
        <WatchStations alerts={state.alerts} />
      </div>

    </div>
  );
}

export default App;
