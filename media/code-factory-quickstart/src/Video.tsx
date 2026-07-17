import React from 'react';
import {
  AbsoluteFill,
  Audio,
  Composition,
  Img,
  Sequence,
  interpolate,
  staticFile,
  useCurrentFrame,
} from 'remotion';

const fps = 30;
const seconds = (value: number) => value * fps;

type Region = {left: number; top: number; width: number; height: number};

const regions: Record<string, Region> = {
  meter: {left: 370, top: 278, width: 1180, height: 104},
  approval: {left: 1020, top: 398, width: 530, height: 74},
  graph: {left: 370, top: 486, width: 1180, height: 76},
  slices: {left: 370, top: 578, width: 635, height: 74},
  mission: {left: 1020, top: 578, width: 530, height: 74},
  proof: {left: 370, top: 666, width: 1180, height: 74},
  compare: {left: 370, top: 756, width: 635, height: 74},
  packs: {left: 1020, top: 756, width: 530, height: 74},
};

const Shell: React.FC<{children?: React.ReactNode; dim?: number}> = ({children, dim = 0}) => (
  <AbsoluteFill style={{backgroundColor: '#f3f7fa', fontFamily: 'Inter, Segoe UI, Arial, sans-serif'}}>
    <Img
      src={staticFile('factory-studio-control-room-1080.png')}
      style={{width: 1920, height: 1080, objectFit: 'cover'}}
    />
    {dim > 0 ? <AbsoluteFill style={{backgroundColor: `rgba(12, 22, 42, ${dim})`}} /> : null}
    {children}
  </AbsoluteFill>
);

const Focus: React.FC<{region: Region}> = ({region}) => {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [0, 10], [0, 1], {extrapolateRight: 'clamp'});
  return (
    <div
      style={{
        position: 'absolute',
        ...region,
        border: '5px solid #2c62d6',
        borderRadius: 8,
        boxShadow: '0 0 0 9999px rgba(12,22,42,.48), 0 12px 40px rgba(19,47,95,.3)',
        opacity,
      }}
    />
  );
};

const Caption: React.FC<{eyebrow: string; title: string; body: string}> = ({eyebrow, title, body}) => {
  const frame = useCurrentFrame();
  const y = interpolate(frame, [0, 15], [28, 0], {extrapolateRight: 'clamp'});
  const opacity = interpolate(frame, [0, 12], [0, 1], {extrapolateRight: 'clamp'});
  return (
    <div
      style={{
        position: 'absolute',
        left: 96,
        bottom: 70,
        width: 800,
        padding: '28px 34px',
        borderRadius: 8,
        background: '#111a2d',
        color: 'white',
        boxShadow: '0 18px 55px rgba(7,16,34,.35)',
        transform: `translateY(${y}px)`,
        opacity,
      }}
    >
      <div style={{fontSize: 22, fontWeight: 800, color: '#7ce3ac', textTransform: 'uppercase'}}>{eyebrow}</div>
      <div style={{fontSize: 48, lineHeight: 1.05, fontWeight: 850, marginTop: 10}}>{title}</div>
      <div style={{fontSize: 25, lineHeight: 1.35, marginTop: 14, color: '#d8e1ef'}}>{body}</div>
    </div>
  );
};

const Intro: React.FC = () => (
  <Shell dim={0.68}>
    <div style={{position: 'absolute', left: 120, top: 210, width: 1180, color: 'white'}}>
      <div style={{fontSize: 28, color: '#7ce3ac', fontWeight: 800}}>CODE FACTORY 0.16</div>
      <div style={{fontSize: 92, lineHeight: 1.02, fontWeight: 900, marginTop: 18}}>From PRD to proof-carrying pull request.</div>
      <div style={{fontSize: 34, lineHeight: 1.35, color: '#d8e1ef', marginTop: 28}}>A 60-second operating guide using the exact Factory Studio UI.</div>
    </div>
  </Shell>
);

const Scene: React.FC<{region: Region; eyebrow: string; title: string; body: string}> = (props) => (
  <Shell>
    <Focus region={props.region} />
    <Caption eyebrow={props.eyebrow} title={props.title} body={props.body} />
  </Shell>
);

const Outro: React.FC = () => (
  <Shell dim={0.72}>
    <div style={{position: 'absolute', left: 180, top: 235, width: 1560, textAlign: 'center', color: 'white'}}>
      <div style={{fontSize: 26, fontWeight: 800, color: '#7ce3ac'}}>BUILD WITH CONTROL. REVIEW WITH PROOF.</div>
      <div style={{fontSize: 76, lineHeight: 1.08, fontWeight: 900, marginTop: 22}}>Install Code Factory and open Studio.</div>
      <div style={{fontFamily: 'Cascadia Code, Consolas, monospace', fontSize: 34, margin: '42px auto', padding: '24px 30px', width: 1080, borderRadius: 8, background: '#0b1220', border: '1px solid #40506b'}}>
        pip install -U code-factory && factory studio
      </div>
      <div style={{fontSize: 29, color: '#d8e1ef'}}>Every external effect remains human-approved.</div>
    </div>
  </Shell>
);

export const QuickStart: React.FC = () => (
  <AbsoluteFill>
    <Audio src={staticFile('narration.wav')} />
    <Sequence from={0} durationInFrames={seconds(7)}><Intro /></Sequence>
    <Sequence from={seconds(7)} durationInFrames={seconds(9)}><Scene region={regions.graph} eyebrow="1 / Compile" title="Start with the Product Graph" body="Paste a PRD. Studio exposes missing journeys, trust boundaries, UX states, approvals, and outcome events before work begins." /></Sequence>
    <Sequence from={seconds(16)} durationInFrames={seconds(9)}><Scene region={regions.slices} eyebrow="2 / Prioritize" title="Choose a vertical value slice" body="Each slice binds UI, behavior, data, tests, observability, and rollback under a deterministic priority score." /></Sequence>
    <Sequence from={seconds(25)} durationInFrames={seconds(9)}><Scene region={regions.approval} eyebrow="3 / Govern" title="Approve one bounded mission" body="A single branch and worktree get scoped context, tools, paths, budgets, and separated builder, checker, and UX roles." /></Sequence>
    <Sequence from={seconds(34)} durationInFrames={seconds(9)}><Scene region={regions.proof} eyebrow="4 / Prove" title="Follow requirement to receipt" body="The proof timeline links stable requirement IDs to code, tests, mutations, screenshots, and the final receipt." /></Sequence>
    <Sequence from={seconds(43)} durationInFrames={seconds(9)}><Scene region={regions.meter} eyebrow="5 / Measure" title="Watch Meter v2 live" body="Track queue, agent, tool, and review time; exact or estimated tokens and cost; retries, rework, throughput, and outcomes." /></Sequence>
    <Sequence from={seconds(52)} durationInFrames={seconds(8)}><Outro /></Sequence>
  </AbsoluteFill>
);

export const VideoRoot: React.FC = () => (
  <Composition
    id="CodeFactoryQuickStart"
    component={QuickStart}
    durationInFrames={seconds(60)}
    fps={fps}
    width={1920}
    height={1080}
  />
);
