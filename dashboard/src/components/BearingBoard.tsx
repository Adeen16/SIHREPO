import React, { useEffect, useRef, useMemo } from 'react';
import type { FlowHost, Alert } from '../types';

interface BearingBoardProps {
  hosts: FlowHost[];
  alerts: Alert[];
}

/**
 * VIGIL v2 — Bearing Board (Host Communication Map)
 * Design decision: Kept radar/sweep metaphor — it reads as surveillance/monitoring
 * which fits the VIGIL brand. Re-skinned to pure monochrome:
 *   - Background: #000000
 *   - Grid rings: rgba(255,255,255,0.10)
 *   - Sweep line: rgba(255,255,255,0.20)
 *   - Normal hosts: rgba(255,255,255,0.55) square dots
 *   - Alerted hosts: #D14B32 square dots (no rounded ring — sharp rectangle only)
 * Note: canvas arc() is used for the radar rings and sweep — this is the only
 * place circles appear, as they represent a physical radar metaphor, not decorative
 * UI chrome. Host dots are rendered as fillRect() (squares) to comply with
 * the no-border-radius rule.
 */
export const BearingBoard: React.FC<BearingBoardProps> = ({ hosts, alerts }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const alertIps = useMemo(() => {
    const ips = new Set<string>();
    alerts.forEach(a => {
      const match = a.flow_id.match(/(\d+\.\d+\.\d+\.\d+)/g);
      if (match) match.forEach(ip => ips.add(ip));
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

    let animationFrameId: number;
    let angleOffset = 0;

    const draw = () => {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;

      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const maxRadius = Math.min(centerX, centerY) - 12;

      // Radar rings — hairline white
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, (maxRadius / 4) * i, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Crosshairs — hairline
      ctx.strokeStyle = 'rgba(255,255,255,0.06)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY - maxRadius);
      ctx.lineTo(centerX, centerY + maxRadius);
      ctx.moveTo(centerX - maxRadius, centerY);
      ctx.lineTo(centerX + maxRadius, centerY);
      ctx.stroke();

      // Sweep line
      angleOffset = (angleOffset + 0.015) % (Math.PI * 2);
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(
        centerX + Math.cos(angleOffset) * maxRadius,
        centerY + Math.sin(angleOffset) * maxRadius
      );
      ctx.strokeStyle = 'rgba(255,255,255,0.18)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Fading sweep trail
      for (let t = 1; t <= 8; t++) {
        const trailAngle = angleOffset - (t * 0.04);
        const alpha = (1 - t / 9) * 0.08;
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(
          centerX + Math.cos(trailAngle) * maxRadius,
          centerY + Math.sin(trailAngle) * maxRadius
        );
        ctx.strokeStyle = `rgba(255,255,255,${alpha})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      const currentHosts = hostsRef.current;
      const currentAlertIps = alertIpsRef.current;
      const particles = particlesRef.current;
      const nowTime = performance.now();

      currentHosts.forEach((host, i) => {
        // Deterministic position from IP hash
        let hash = 0;
        for (let j = 0; j < host.ip.length; j++) {
          hash = host.ip.charCodeAt(j) + ((hash << 5) - hash);
        }
        const angle = (Math.abs(hash) % 360) * (Math.PI / 180);
        const targetRadius = maxRadius * (0.15 + (i % 8) * 0.1);

        const tx = centerX + Math.cos(angle) * targetRadius;
        const ty = centerY + Math.sin(angle) * targetRadius;

        let p = particles.get(host.ip);
        if (!p) {
          p = { x: tx, y: ty, spawn: nowTime };
          particles.set(host.ip, p);
        }

        p.x += (tx - p.x) * 0.1;
        p.y += (ty - p.y) * 0.1;

        const isAlerted = currentAlertIps.has(host.ip);
        const age = nowTime - p.spawn;
        const opacity = Math.min(1.0, age / 150);

        ctx.save();
        ctx.globalAlpha = opacity;

        if (isAlerted) {
          // Alerted host — red 5×5 square (no border-radius — use fillRect)
          ctx.fillStyle = '#D14B32';
          ctx.fillRect(p.x - 3, p.y - 3, 6, 6);

          // Alert indicator — thin red rectangle frame (not circle)
          ctx.strokeStyle = `rgba(209,75,50,${0.4 * opacity})`;
          ctx.lineWidth = 1;
          ctx.strokeRect(p.x - 8, p.y - 8, 16, 16);
        } else {
          // Normal host — dim white 3×3 square
          ctx.fillStyle = `rgba(255,255,255,${0.5 * opacity})`;
          ctx.fillRect(p.x - 1.5, p.y - 1.5, 3, 3);
        }

        ctx.restore();
      });

      // Center origin marker
      ctx.fillStyle = 'rgba(255,255,255,0.30)';
      ctx.fillRect(centerX - 2, centerY - 2, 4, 4);

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
    <div
      ref={containerRef}
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', background: '#000' }}
    >
      <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />
    </div>
  );
};
