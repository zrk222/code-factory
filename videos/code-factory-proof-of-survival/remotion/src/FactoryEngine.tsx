import React from 'react';
import {AbsoluteFill, Img, interpolate, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';

// Captures show actual local evidence; diagrams explain requirements, not executed activity.
const scenes = [
  {title:'A code audit factory.', tag:'CODE FACTORY + FORGELINE', body:'Connect code changes to checks, evidence and actionable repairs.', points:['Architecture and workflow integrity','Python static analysis','Runtime and behavioral evidence']},
  {title:'Stronger test-oracle analysis.', tag:'FIXED', body:'Follow bounded local imports and inherited test mixins. Challenge vacuous assertions without treating every helper as hollow.', points:['Imported assertion helpers','Inherited unittest assertions','Explicit tenant-read bindings']},
  {title:'Six runtime lanes. One output contract.', tag:'IMPROVED', body:'Malformed, oversized or non-finite evaluator results remain incomplete.', points:['Stateful invariants and tenant isolation','Recovery and API compatibility','Migration integrity and performance']},
  {title:'See the operating picture.', tag:'ACTUAL LOCAL DASHBOARD', body:'Inspect telemetry, stale evidence and the next declared action.', asset:'graph-ops-dashboard-current.png'},
  {title:'Every reported test stays inspectable.', tag:'ACTUAL LOCAL TEST RESULTS', body:'415 targeted tests passed in this capture. JUnit evidence is local and unbound; missing runtime receipts stay visible.', asset:'graph-ops-audit-telemetry-current.png'},
  {title:'Give agents an actionable repair.', tag:'ADDED · REPAIR PACKETS', body:'Each packet binds its candidate and finding. The host agent performs the work.', points:['Reproduce before changing code','Patch within scope and rerun negative controls','Obtain separate specialty AI review']},
  {title:'Keep the failure. Stop unsafe retries.', tag:'EVIDENCE REQUIREMENTS', body:'Finding context is untrusted data. A reviewer role is a requirement, not a completed review.', points:['Before failure + patch diff + after observation','Negative control + independent agent review','Stop on drift, new failures or exhausted budget']},
  {title:'Audit. Repair. Verify again.', tag:'OPEN SOURCE · LOCAL FIRST', body:'Use CF/FL with Junie, Codex or your preferred agent. Receipts support review; they do not certify software or approve releases.', points:['Inspect the source and current evidence','Run the applicable audit locally','github.com/zrk222/code-factory']},
];
export const FactoryEngine = () => {
  const frame=useCurrentFrame(); const {fps}=useVideoConfig();
  const length=7.5*fps; const index=Math.min(scenes.length-1,Math.floor(frame/length));
  const scene=scenes[index]; const local=frame-index*length;
  const fade=interpolate(local,[0,12,length-12,length],[0,1,1,0],{extrapolateLeft:'clamp',extrapolateRight:'clamp'});
  return <AbsoluteFill style={{background:'#d5c2a3',fontFamily:'Arial, sans-serif',color:'#242b24'}}>
    <AbsoluteFill style={{opacity:fade,padding:70}}>
      <div style={{display:'flex',alignItems:'center',gap:20}}><Img src={staticFile('factoryline-logo-480.png')} style={{width:76,height:76,objectFit:'contain'}}/><span style={{fontSize:24,fontWeight:700,letterSpacing:2}}>{scene.tag}</span></div>
      <h1 style={{fontSize:64,lineHeight:1.08,maxWidth:1100,margin:'32px 0 20px'}}>{scene.title}</h1>
      <p style={{fontSize:28,lineHeight:1.5,maxWidth:scene.asset?850:1300,margin:0}}>{scene.body}</p>
      {scene.asset?<div style={{position:'absolute',right:70,bottom:105,width:980,height:585,background:'#101929',borderRadius:16,overflow:'hidden'}}><Img src={staticFile(scene.asset)} style={{width:'100%',height:'100%',objectFit:'contain'}}/></div>:<div style={{marginTop:50,display:'grid',gap:20}}>{scene.points?.map((point,i)=><div key={point} style={{display:'flex',gap:24,alignItems:'center',padding:'20px 28px',border:'1px solid #8a775d',borderRadius:12,background:'#e7d7bd',maxWidth:1450}}><span style={{fontFamily:'Consolas, monospace',fontSize:36,fontWeight:700,color:'#126333'}}>{String(i+1).padStart(2,'0')}</span><span style={{fontSize:30}}>{point}</span></div>)}</div>}
      <div style={{position:'absolute',bottom:46,left:70,right:70,display:'flex',justifyContent:'space-between',fontSize:19}}><span>Current source preview · October 8, 2026 · silent captioned walkthrough</span><span style={{fontFamily:'Consolas, monospace',color:'#126333'}}>{String(index+1).padStart(2,'0')} / 08</span></div>
    </AbsoluteFill>
  </AbsoluteFill>;
};
