import React, { useEffect, useRef } from 'react';
import type { WindowMetrics } from '../types';

interface WaterfallProps {
  currentMetrics: WindowMetrics | null;
}

/**
 * VIGIL v2 — Traffic Waterfall
 * Re-skinned to monochrome with red-only accent.
 * Same scrolling mechanic preserved.
 * Color mapping:
 *   - Normal (< 30% max): rgba(255,255,255,0.25) — dim white
 *   - Elevated (30–70%):  rgba(255,255,255,0.55) — bright white
 *   - High (> 70%):       #D14B32 — red (the only accent)
 */
export const Waterfall: React.FC<WaterfallProps> = ({ currentMetrics }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const historyRef = useRef<number[]>([]);
  const lastDataTimeRef = useRef(performance.now());
  const MAX_HISTORY = 100;

  useEffect(() => {
    if (currentMetrics) {
      historyRef.current.push(currentMetrics.packets_per_second);
      if (historyRef.current.length > MAX_HISTORY) {
        historyRef.current.shift();
      }
      lastDataTimeRef.current = performance.now();
    } else {
      historyRef.current = [];
    }
  }, [currentMetrics]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let lastDrawTime = performance.now();

    const draw = (time: number) => {
      if (time - lastDrawTime > 16) {
        lastDrawTime = time;

        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;

        // Pure black background
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        const data = historyRef.current;
        if (data.length === 0) {
          animationFrameId = requestAnimationFrame(draw);
          return;
        }

        const maxPps = Math.max(100, ...data);
        const spacing = canvas.width / MAX_HISTORY;
        const barWidth = Math.max(2, spacing - 1);

        const timeSinceData = time - lastDataTimeRef.current;
        const progress = Math.min(1.0, timeSinceData / 1000);
        const slideOffset = (1.0 - progress) * spacing;

        // Grid lines — hairline white at 8% opacity
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.lineWidth = 1;

        for (let i = 1; i <= 3; i++) {
          const y = canvas.height * (i / 4);
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(canvas.width, y);
          ctx.stroke();
        }

        for (let i = 0; i <= MAX_HISTORY; i += 10) {
          const x = canvas.width - (i * spacing) + slideOffset;
          if (x > 0 && x < canvas.width) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, canvas.height);
            ctx.stroke();
          }
        }

        // Bars — monochrome + red at high intensity
        for (let i = 0; i < data.length; i++) {
          const val = data[i];
          const ratio = val / maxPps;
          const h = ratio * (canvas.height * 0.9);
          const x = canvas.width - ((data.length - i) * spacing) + slideOffset;
          const y = canvas.height - h;

          if (ratio > 0.7) {
            ctx.fillStyle = '#D14B32'; // Red — only for high intensity
          } else if (ratio > 0.3) {
            ctx.fillStyle = 'rgba(255,255,255,0.60)';
          } else {
            ctx.fillStyle = 'rgba(255,255,255,0.25)';
          }

          ctx.fillRect(x, y, barWidth, h);
        }

        // Current PPS label — top right
        if (data.length > 0) {
          const current = data[data.length - 1];
          ctx.font = '400 9px JetBrains Mono';
          ctx.fillStyle = 'rgba(255,255,255,0.28)';
          ctx.textAlign = 'right';
          ctx.textBaseline = 'top';
          ctx.fillText(`PEAK ${Math.round(maxPps).toLocaleString()} PKT/S`, canvas.width - 8, 6);
          if (current / maxPps > 0.7) {
            ctx.fillStyle = '#D14B32';
          } else {
            ctx.fillStyle = 'rgba(255,255,255,0.62)';
          }
          ctx.fillText(`${Math.round(current).toLocaleString()} PKT/S`, canvas.width - 8, 18);
        }
      }
      animationFrameId = requestAnimationFrame(draw);
    };

    animationFrameId = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  return (
    <div ref={containerRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
      <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />
    </div>
  );
};
