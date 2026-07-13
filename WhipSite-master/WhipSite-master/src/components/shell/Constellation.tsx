"use client";
import { useEffect, useRef } from "react";

// Animated plexus background (reduced-motion aware), ported from the prototype.
export function Constellation() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let w = 0;
    let h = 0;
    let pts: { x: number; y: number; vx: number; vy: number }[] = [];
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    function resize() {
      w = canvas!.clientWidth;
      h = canvas!.clientHeight;
      canvas!.width = w * DPR;
      canvas!.height = h * DPR;
      ctx!.setTransform(DPR, 0, 0, DPR, 0, 0);
      const count = Math.min(80, Math.floor((w * h) / 22000));
      pts = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
      }));
    }
    function draw() {
      ctx!.clearRect(0, 0, w, h);
      for (const p of pts) {
        if (!reduce) {
          p.x += p.vx;
          p.y += p.vy;
        }
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x;
          const dy = pts[i].y - pts[j].y;
          const d = Math.hypot(dx, dy);
          if (d < 130) {
            ctx!.strokeStyle = `rgba(37,99,235,${0.1 * (1 - d / 130)})`;
            ctx!.lineWidth = 1;
            ctx!.beginPath();
            ctx!.moveTo(pts[i].x, pts[i].y);
            ctx!.lineTo(pts[j].x, pts[j].y);
            ctx!.stroke();
          }
        }
      }
      for (const p of pts) {
        ctx!.fillStyle = "rgba(96,140,235,0.5)";
        ctx!.beginPath();
        ctx!.arc(p.x, p.y, 1.2, 0, 7);
        ctx!.fill();
      }
      if (!reduce) raf = requestAnimationFrame(draw);
    }
    resize();
    draw();
    const ro = new ResizeObserver(() => {
      resize();
      if (reduce) draw();
    });
    ro.observe(canvas);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);
  return <canvas ref={ref} className="whip-constellation" aria-hidden="true" />;
}
