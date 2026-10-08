import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { build } from 'esbuild';
import os from 'node:os';
import { randomUUID } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
async function renderTsx(file, exports, remotionStub) {
  const source = readFileSync(file, 'utf8');
  const transformed = await build({ stdin: { contents: source, resolveDir: path.dirname(file), sourcefile: file, loader: 'tsx' }, write: false, bundle: true, format: 'esm', platform: 'node', external: ['react'], plugins: [{
    name: 'remotion-test-runtime',
    setup(build) {
      build.onResolve({ filter: /^remotion$/ }, () => ({ path: remotionStub, namespace: 'test-remotion' }));
      build.onLoad({ filter: /.*/, namespace: 'test-remotion' }, () => ({ contents: remotionStub, loader: 'js' }));
    },
  }] });
  const modulePath = path.join(path.dirname(file), `.cf-engine-test-${randomUUID()}.mjs`);
  writeFileSync(modulePath, transformed.outputFiles[0].text);
  try {
    const loaded = await import(pathToFileURL(modulePath).href);
    return exports(loaded);
  } finally {
    rmSync(modulePath, { force: true });
  }
}

test('FactoryEngine renders real frame state and clamps to the final scene', async () => {
  const markup = await renderTsx(path.join(here, 'FactoryEngine.tsx'), ({ FactoryEngine }) => {
    const html = renderToStaticMarkup(React.createElement(FactoryEngine));
    assert.match(html, /FIXED/);
    assert.match(html, /Stronger test-oracle analysis/);
    assert.match(html, /02 \/ 08/);
    return html;
  }, `export const useCurrentFrame=()=>225; export const useVideoConfig=()=>({fps:30}); export const interpolate=(v)=>Math.max(0,Math.min(1,(v[0]??0))); export const staticFile=(v)=>v; export const AbsoluteFill='div'; export const Img='img';`);
  assert.match(markup, /background:#d5c2a3/);
  const finalMarkup = await renderTsx(path.join(here, 'FactoryEngine.tsx'), ({ FactoryEngine }) => {
    const html = renderToStaticMarkup(React.createElement(FactoryEngine));
    assert.match(html, /OPEN SOURCE · LOCAL FIRST/);
    assert.match(html, /08 \/ 08/);
    return html;
  }, `export const useCurrentFrame=()=>99999; export const useVideoConfig=()=>({fps:30}); export const interpolate=(v)=>1; export const staticFile=(v)=>v; export const AbsoluteFill='div'; export const Img='img';`);
  assert.match(finalMarkup, /Audit\. Repair\. Verify again\./);
  assert.match(finalMarkup, /08 \/ 08/);
});

test('Root registers the named composition with its production frame geometry', async () => {
  const file = path.join(here, 'root.tsx');
  const source = readFileSync(file, 'utf8').replace("import { FactoryEngine } from './FactoryEngine';", "const FactoryEngine = function FactoryEngine() {};").replace("import { Composition } from 'remotion';", "import React from 'react'; import { Composition } from 'remotion';");
  const transformed = await build({ stdin: { contents: source, resolveDir: path.dirname(file), sourcefile: file, loader: 'tsx' }, write: false, bundle: true, format: 'esm', platform: 'node', external: ['react'], plugins: [{
    name: 'remotion-root-test-runtime', setup(build) {
      build.onResolve({ filter: /^remotion$/ }, () => ({ path: 'stub', namespace: 'test-remotion' }));
      build.onLoad({ filter: /.*/, namespace: 'test-remotion' }, () => ({ contents: `export const Composition=(props)=>globalThis.__composition(props);`, loader: 'js' }));
    },
  }] });
  const modulePath = path.join(here, `.cf-root-test-${process.pid}.mjs`);
  writeFileSync(modulePath, transformed.outputFiles[0].text);
  const url = pathToFileURL(modulePath).href;
  let props;
  globalThis.__composition = (value) => { props = value; return React.createElement('div', null, value.id); };
  try {
    const { Root } = await import(url);
    const html = renderToStaticMarkup(React.createElement(Root));
    assert.match(html, /CodeFactoryFactoryEngine/);
    assert.equal(props.id, 'CodeFactoryFactoryEngine');
    assert.equal(props.durationInFrames, 1800);
    assert.equal(props.fps, 30);
    assert.deepEqual([props.width, props.height], [1920, 1080]);
    assert.equal(typeof props.component, 'function');
  } finally {
    delete globalThis.__composition;
    rmSync(modulePath, { force: true });
  }
});
