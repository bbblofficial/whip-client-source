"use client";
// Metallic WHIP "W" monogram + brand lockup.
export function LogoMark({ size = 46 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="whipLogoG" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#f4f7ff" />
          <stop offset="45%" stopColor="#aeb8cc" />
          <stop offset="55%" stopColor="#5b6376" />
          <stop offset="100%" stopColor="#c7cedd" />
        </linearGradient>
      </defs>
      <g stroke="url(#whipLogoG)" strokeWidth="6" strokeLinejoin="round" strokeLinecap="round" fill="none">
        <path d="M22 18 L22 64 Q22 80 38 80 Q50 80 50 64 L50 30" />
        <path d="M50 30 L50 64 Q50 80 62 80 Q78 80 78 64 L78 18" />
        <path d="M50 30 L50 14" strokeWidth="5" opacity="0.85" />
      </g>
    </svg>
  );
}

export function BrandLockup({ compact }: { compact?: boolean }) {
  return (
    <div className="whip-brand">
      <LogoMark size={compact ? 34 : 52} />
      {!compact && (
        <>
          <div className="whip-brand__name">WHIP</div>
          <div className="whip-brand__sub">SYSTEM CONTROL</div>
          <div className="whip-brand__ver">V1.1.0-METAL</div>
        </>
      )}
    </div>
  );
}
