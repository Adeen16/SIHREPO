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
  const MAX_HISTORY = 100; // Keep last 100 data points

  useEffect(() => {
    if (currentMetrics) {
      historyRef.current.push(currentMetrics.packets_per_second);
      if (historyRef.current.length > MAX_HISTORY) {
        historyRef.current.shift();
      }
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
      // Limit to ~30fps for drawing
      if (time - lastDrawTime > 33) {
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

        const maxPps = Math.max(100, ...data); // dynamic scaling
        const barWidth = Math.max(2, (canvas.width / MAX_HISTORY) - 1);
        const spacing = canvas.width / MAX_HISTORY;
        
        // Draw bars from right to left (newest on right)
        for (let i = 0; i < data.length; i++) {
          const val = data[i];
          const ratio = val / maxPps;
          const h = ratio * (canvas.height * 0.9); // max 90% height
          
          const x = canvas.width - ((data.length - i) * spacing);
          const y = canvas.height - h;
          
          // Color logic based on volume
          if (ratio > 0.7) {
            ctx.fillStyle = '#C4432B'; // Red for very high
          } else if (ratio > 0.3) {
            ctx.fillStyle = '#D99A3D'; // Amber for medium
          } else {
            ctx.fillStyle = '#3E8E88'; // Cyan for low
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

