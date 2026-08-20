import React from 'react';
import {
  AbsoluteFill,
  Img,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';

const scenes = [
  { start: 0, end: 270, eyebrow: 'THE QUESTION', title: ['AI WRITES FAST.', 'CAN THE TEST SAY NO?'], note: 'A passing check is not evidence until it has a declared failure path.', kind: 'question' },
  { start: 270, end: 540, eyebrow: 'LOCAL-FIRST PROOF LANE', title: ['INTENT → BUILD → VERIFY', 'HUMANS STAY IN CONTROL.'], note: 'A visible chain of proof objects, not an opaque agent claim.', kind: 'lane' },
  { start: 540, end: 840, eyebrow: 'VIBE CODING', title: ['START WITH THE OUTCOME.', 'SEE WHAT THE TESTS PROVE.'], note: 'Plain language in. Reviewable MVP and evidence out.', kind: 'mvp', asset: 'factory-studio-mvp-1280x800.png' },
  { start: 840, end: 1170, eyebrow: 'SURVIVAL GAUNTLET', title: ['DECLARED SCENARIOS.', 'REAL COMMAND.'], note: 'A green result is challenged against the failure you chose.', kind: 'gauntlet' },
  { start: 1170, end: 1500, eyebrow: 'HONEST OUTCOMES', title: ['SURVIVED.', 'HOLLOW. BLOCKED.'], note: 'The card records the command, evidence, and next safe action.', kind: 'card' },
  { start: 1500, end: 1830, eyebrow: 'TEAM CONTROL', title: ['NAMED APPROVALS.', 'BOUNDED REPAIR.'], note: 'Deterministic checks and evidence remain reviewable end to end.', kind: 'team' },
  { start: 1830, end: 2160, eyebrow: 'GRAPH OPS', title: ['ONE OPERATING PICTURE.', 'THE NEXT SAFE ACTION.'], note: 'Current proof, stale work, blocked gates, and ownership.', kind: 'graph', asset: 'graph-ops-studio-1280x800.png' },
  { start: 2160, end: 2430, eyebrow: 'OPTIONAL CONTINUITY', title: ['CONTEXT IS NOT PROOF.', 'EVIDENCE STAYS BOUND.'], note: 'Verified, purpose-scoped references never replace human judgment.', kind: 'continuity' },
  { start: 2430, end: 2700, eyebrow: 'CODE FACTORY', title: ['BUILD QUICKLY.', 'VERIFY HONESTLY.'], note: 'Open source. Local first. Keep control.', kind: 'cta', asset: 'factoryline-logo-480.png' },
] as const;

const COLORS = {
  canvas: '#07111b',
  panel: '#102535',
  panelSoft: '#0a1824',
  mint: '#35d7b8',
  sky: '#7dd3fc',
  text: '#f3f8fc',
  muted: '#9bb1c1',
  coral: '#f4b860',
  danger: '#ff7b72',
};

const frameOpacity = (frame: number, start: number, end: number) => interpolate(frame, [start, start + 12, end - 15, end], [0, 1, 1, 0], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

const Node = ({ x, y, label, active, bad = false }: { x: number; y: number; label: string; active: boolean; bad?: boolean }) => (
  <div style={{ position: 'absolute', left: x, top: y, width: 178, height: 70, border: `1px solid ${bad ? COLORS.danger : active ? COLORS.mint : '#31546a'}`, background: active ? 'rgba(53,215,184,0.12)' : 'rgba(16,37,53,0.9)', boxShadow: active ? `0 0 42px ${bad ? 'rgba(255,123,114,0.28)' : 'rgba(53,215,184,0.25)'}` : 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'JetBrains Mono, monospace', fontSize: 17, letterSpacing: 1.3, color: bad ? COLORS.danger : active ? COLORS.mint : COLORS.muted }}>
    {label}
  </div>
);

const FactoryGrid = ({ kind }: { kind: string }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const progress = spring({ frame: frame % 330, fps, config: { damping: 200, stiffness: 70, mass: 1 } });
  const active = Math.min(3, Math.floor(progress * 4));
  const isGauntlet = kind === 'gauntlet';
  const isCard = kind === 'card';
  const isContinuity = kind === 'continuity';

  return (
    <div style={{ position: 'absolute', right: 95, top: 185, width: 890, height: 600, border: '1px solid #1d3d51', overflow: 'hidden', background: 'linear-gradient(135deg, rgba(16,37,53,0.98), rgba(7,17,27,0.88))' }}>
      <div style={{ position: 'absolute', inset: 0, opacity: 0.3, backgroundImage: 'linear-gradient(rgba(125,211,252,0.12) 1px, transparent 1px), linear-gradient(90deg, rgba(125,211,252,0.12) 1px, transparent 1px)', backgroundSize: '44px 44px' }} />
      <div style={{ position: 'absolute', left: 38, top: 38, fontFamily: 'JetBrains Mono, monospace', letterSpacing: 2, color: COLORS.sky, fontSize: 14 }}>FACTORY / LIVE PROOF PATH</div>
      {[0, 1, 2].map((index) => <div key={index} style={{ position: 'absolute', left: 180 + index * 210, top: 308, width: 218, height: 2, background: index < active ? COLORS.mint : '#31546a', transformOrigin: 'left', transform: `scaleX(${index < active ? 1 : 0.24})`, boxShadow: index < active ? `0 0 12px ${COLORS.mint}` : 'none' }} />)}
      <Node x={40} y={275} label={isContinuity ? 'REFERENCE' : 'INTENT'} active={active >= 0} />
      <Node x={250} y={275} label={isGauntlet ? 'SCENARIO' : 'BUILD'} active={active >= 1} />
      <Node x={460} y={275} label={isGauntlet ? 'COMMAND' : 'VERIFY'} active={active >= 2} />
      <Node x={670} y={275} label={isCard ? 'SURVIVAL CARD' : isContinuity ? 'BOUNDARY' : 'REVIEW'} active={active >= 3} bad={isGauntlet && active >= 3} />
      {isCard && <div style={{ position: 'absolute', left: 125, top: 445, display: 'flex', gap: 28 }}>
        {['SURVIVED', 'HOLLOW', 'BLOCKED'].map((state, index) => <div key={state} style={{ width: 182, height: 78, border: `1px solid ${index === 0 ? COLORS.mint : index === 1 ? COLORS.danger : COLORS.coral}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'JetBrains Mono, monospace', color: index === 0 ? COLORS.mint : index === 1 ? COLORS.danger : COLORS.coral, fontSize: 18 }}>{state}</div>)}
      </div>}
      {isContinuity && <div style={{ position: 'absolute', left: 76, top: 455, width: 700, borderTop: `1px solid ${COLORS.mint}`, paddingTop: 18, display: 'flex', justifyContent: 'space-between', fontFamily: 'JetBrains Mono, monospace', fontSize: 15, color: COLORS.muted }}><span>VERIFIED REF</span><span>PURPOSE SCOPED</span><span>HUMAN REVIEW</span></div>}
    </div>
  );
};

const EvidencePlate = ({ asset, title }: { asset: string; title: string[] }) => {
  const frame = useCurrentFrame();
  const local = frame % 330;
  const scale = interpolate(local, [0, 55, 300], [0.92, 1, 1.02], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  return <div style={{ position: 'absolute', right: 105, top: 170, width: 900, height: 580, transform: `perspective(1600px) rotateY(${-6 + scale * 6}deg) rotateX(${5 - scale * 5}deg) scale(${scale})`, transformOrigin: 'center', border: '1px solid #31546a', background: COLORS.panelSoft, boxShadow: '0 38px 95px rgba(0,0,0,0.44)', overflow: 'hidden' }}>
    <Img src={staticFile(asset)} style={{ width: '100%', height: '100%', objectFit: 'cover', opacity: 0.9 }} />
    <div style={{ position: 'absolute', left: 22, top: 20, padding: '9px 12px', background: 'rgba(7,17,27,0.9)', border: `1px solid ${COLORS.mint}`, fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: COLORS.mint, letterSpacing: 1.4 }}>{title[0]}</div>
  </div>;
};

export const FactoryEngine = () => {
  const frame = useCurrentFrame();
  const scene = scenes.find((item) => frame >= item.start && frame < item.end) ?? scenes[scenes.length - 1];
  const local = frame - scene.start;
  const opacity = frameOpacity(frame, scene.start, scene.end);
  const titleProgress = spring({ frame: local - 14, fps: 30, config: { damping: 200, stiffness: 90 } });
  const noteProgress = spring({ frame: local - 60, fps: 30, config: { damping: 200, stiffness: 70 } });
  const isCta = scene.kind === 'cta';
  const titleFontSize = isCta ? 84 : scene.kind === 'mvp' ? 54 : 67;
  const noteTop = scene.kind === 'graph' ? 570 : isCta ? 500 : scene.kind === 'mvp' ? 500 : 486;

  return (
    <AbsoluteFill style={{ background: COLORS.canvas, color: COLORS.text, fontFamily: 'Inter, Arial, sans-serif', opacity }}>
      <div style={{ position: 'absolute', inset: 0, backgroundImage: 'radial-gradient(circle at 76% 24%, rgba(53,215,184,0.12), transparent 25%), linear-gradient(rgba(125,211,252,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(125,211,252,0.055) 1px, transparent 1px)', backgroundSize: 'auto, 52px 52px, 52px 52px' }} />
      <div style={{ position: 'absolute', left: 88, top: 72, display: 'flex', alignItems: 'center', gap: 16 }}><div style={{ width: 12, height: 12, background: COLORS.mint, boxShadow: `0 0 18px ${COLORS.mint}` }} /><span style={{ fontFamily: 'JetBrains Mono, monospace', color: COLORS.sky, letterSpacing: 2.8, fontSize: 15 }}>{scene.eyebrow}</span></div>
      <div style={{ position: 'absolute', left: 88, top: isCta ? 265 : 265, width: 770, transform: `translateY(${interpolate(titleProgress, [0, 1], [48, 0])}px)`, opacity: titleProgress }}>
        {scene.title.map((line, index) => <div key={line} style={{ fontSize: titleFontSize, lineHeight: 1.02, fontWeight: 750, letterSpacing: -2.2, marginBottom: 14, color: index === 1 ? COLORS.mint : COLORS.text }}>{line}</div>)}
      </div>
      <div style={{ position: 'absolute', left: 92, top: noteTop, width: 650, fontSize: 24, lineHeight: 1.45, color: COLORS.muted, transform: `translateY(${interpolate(noteProgress, [0, 1], [26, 0])}px)`, opacity: noteProgress }}>{scene.note}</div>
      {scene.asset && scene.kind !== 'cta' ? <EvidencePlate asset={scene.asset} title={scene.title} /> : <FactoryGrid kind={scene.kind} />}
      {isCta && <div style={{ position: 'absolute', right: 215, top: 235, width: 520, height: 520, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', border: `1px solid ${COLORS.mint}`, background: 'rgba(16,37,53,0.7)', boxShadow: `0 0 80px rgba(53,215,184,0.16)` }}><Img src={staticFile('factoryline-logo-480.png')} style={{ width: 230, height: 230, objectFit: 'contain' }} /><div style={{ marginTop: 28, fontFamily: 'JetBrains Mono, monospace', letterSpacing: 2, color: COLORS.mint, fontSize: 17 }}>OPEN SOURCE · LOCAL FIRST</div></div>}
      <div style={{ position: 'absolute', left: 88, right: 88, bottom: 58, height: 2, background: '#1d3d51' }}><div style={{ height: 2, background: COLORS.mint, width: `${interpolate(frame, [scene.start, scene.end], [0, 100], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' })}%` }} /></div>
      <div style={{ position: 'absolute', right: 90, bottom: 77, fontFamily: 'JetBrains Mono, monospace', fontSize: 13, letterSpacing: 1.8, color: COLORS.muted }}>PROOF OF SURVIVAL / {String(scenes.indexOf(scene) + 1).padStart(2, '0')}</div>
    </AbsoluteFill>
  );
};
