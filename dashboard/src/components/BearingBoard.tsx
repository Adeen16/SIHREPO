import React, { useEffect, useRef, useMemo } from 'react';
import type { FlowHost, Alert } from '../types';

interface BearingBoardProps {
  hosts: FlowHost[];
  alerts: Alert[];
}

export const BearingBoard: React.FC<BearingBoardProps> = ({ hosts, alerts }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // In a real app we'd map threat IPs. We'll use a mocked list from alerts for visualization
  const alertIps = useMemo(() => {
    const ips = new Set<string>();
    alerts.forEach(a => {
      // Very naive IP extraction for visual demo
      const match = a.flow_id.match(/(\d+\.\d+\.\d+\.\d+)/g);
      if (match) {
        match.forEach(ip => ips.add(ip));
      }
    });
    return ips;
  }, [alerts]);

  const hostsRef = useRef(hosts);
  const alertIpsRef = useRef(alertIps);
  const particlesRef = useRef(new Map<string, any>());
  
  useEffect(() => {
    hostsRef.current = hosts;
    alertIpsRef.current = alertIps;
  }, [hosts, alertIps]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const maxRadius = Math.min(centerX, centerY) - 10;

    let animationFrameId: number;
    let angleOffset = 0;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Draw Grid / Radar rings
      ctx.strokeStyle = '#2B2E29'; // grid-line
      ctx.lineWidth = 1;
      
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, (maxRadius / 4) * i, 0, Math.PI * 2);
        ctx.stroke();
      }
      
      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(centerX, centerY - maxRadius);
      ctx.lineTo(centerX, centerY + maxRadius);
      ctx.moveTo(centerX - maxRadius, centerY);
      ctx.lineTo(centerX + maxRadius, centerY);
      ctx.stroke();

      // Sweep line
      angleOffset = (angleOffset + 0.02) % (Math.PI * 2);
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(angleOffset) * maxRadius, centerY + Math.sin(angleOffset) * maxRadius);
      ctx.strokeStyle = 'rgba(62, 142, 136, 0.4)'; // accent-cyan faded
      ctx.lineWidth = 2;
      ctx.stroke();

      const currentHosts = hostsRef.current;
      const currentAlertIps = alertIpsRef.current;
      const particles = particlesRef.current;
      const nowTime = performance.now();

      // Plot points
      currentHosts.forEach((host, i) => {
        // Angle based on string hash of IP
        let hash = 0;
        for (let j = 0; j < host.ip.length; j++) {
          hash = host.ip.charCodeAt(j) + ((hash << 5) - hash);
        }
        const angle = (Math.abs(hash) % 360) * (Math.PI / 180);
        
        // Radius based on recency (closer to center = more recent)
        const targetRadius = maxRadius * (0.2 + (i % 8) * 0.1);

        const tx = centerX + Math.cos(angle) * targetRadius;
        const ty = centerY + Math.sin(angle) * targetRadius;
        
        let p = particles.get(host.ip);
        if (!p) {
          p = { x: tx, y: ty, spawn: nowTime };
          particles.set(host.ip, p);
        }
        
        // Smoothly interpolate position
        p.x += (tx - p.x) * 0.1;
        p.y += (ty - p.y) * 0.1;

        const isAlerted = currentAlertIps.has(host.ip);
        const age = nowTime - p.spawn;
        const opacity = Math.min(1.0, age / 150);

        ctx.save();
        ctx.globalAlpha = opacity;
        
        // Dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, isAlerted ? 4 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isAlerted ? '#C4432B' : '#3E8E88'; // red or cyan
        ctx.fill();

        // Optional fading trail or ping
        if (isAlerted) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, 8, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(196, 67, 43, ${0.5 * opacity})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
        ctx.restore();
      });

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    const handleResize = () => {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <div ref={containerRef} className="absolute inset-0 w-full h-full bg-[#12130F]">
      <canvas ref={canvasRef} className="w-full h-full block" />
    </div>
  );
};
