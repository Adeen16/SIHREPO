import React, { useEffect, useRef, useState } from 'react';
import type { WindowMetrics } from '../types';

interface WaterfallProps {
  currentMetrics: WindowMetrics | null;
}

export const Waterfall: React.FC<WaterfallProps> = ({ currentMetrics }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  
  // History buffer for the bars
  const historyRef = useRef<number[]>([]);
  const lastDataTimeRef = useRef(performance.now());
  const MAX_HISTORY = 100; // Keep last 100 data points

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
      // Limit to ~60fps for smoother scroll
      if (time - lastDrawTime > 16) {
        lastDrawTime = time;
        
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
        
        ctx.fillStyle = '#1B1D17';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        const data = historyRef.current;
        if (data.length === 0) {
          animationFrameId = requestAnimationFrame(draw);
          return;
        }

        const maxPps = Math.max(100, ...data);
        const spacing = canvas.width / MAX_HISTORY;
        const barWidth = Math.max(2, spacing - 1);
        
        // Smooth slide offset
        const timeSinceData = time - lastDataTimeRef.current;
        const progress = Math.min(1.0, timeSinceData / 1000); // Assumes 1s arrival
        const slideOffset = (1.0 - progress) * spacing;
        
        // Draw grid lines
        ctx.strokeStyle = '#2B2E29';
        ctx.lineWidth = 1;
        
        // Value (horizontal) gridlines
        for (let i = 1; i <= 3; i++) {
          const y = canvas.height * (i / 4);
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(canvas.width, y);
          ctx.stroke();
        }

        // Time (vertical) gridlines every 10 updates
        for (let i = 0; i <= MAX_HISTORY; i += 10) {
          const x = canvas.width - (i * spacing) + slideOffset;
          if (x > 0 && x < canvas.width) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, canvas.height);
            ctx.stroke();
          }
        }
        
        // Draw bars from right to left
        for (let i = 0; i < data.length; i++) {
          const val = data[i];
          const ratio = val / maxPps;
          const h = ratio * (canvas.height * 0.9);
          
          const x = canvas.width - ((data.length - i) * spacing) + slideOffset;
          const y = canvas.height - h;
          
          if (ratio > 0.7) {
            ctx.fillStyle = '#C4432B';
          } else if (ratio > 0.3) {
            ctx.fillStyle = '#D99A3D';
          } else {
            ctx.fillStyle = '#3E8E88';
          }
          
          ctx.fillRect(x, y, barWidth, h);
        }
      }
      animationFrameId = requestAnimationFrame(draw);
    };

    animationFrameId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div ref={containerRef} className="absolute inset-0 w-full h-full p-2">
      <canvas ref={canvasRef} className="w-full h-full block" />
    </div>
  );
};

