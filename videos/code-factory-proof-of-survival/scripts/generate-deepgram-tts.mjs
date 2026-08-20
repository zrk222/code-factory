#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import path from 'node:path';

const execFileAsync = promisify(execFile);

const projectRoot = path.resolve(process.cwd());
const scriptPath = path.join(projectRoot, 'SCRIPT.md');
const outputDir = path.join(projectRoot, 'assets', 'audio');
const outputPath = path.join(outputDir, 'narration-deepgram.mp3');
const metadataPath = path.join(outputDir, 'narration-deepgram.json');
const apiKey = process.env.DEEPGRAM_API_KEY;
const requestedSegment = process.argv.indexOf('--segment') >= 0
  ? Number(process.argv[process.argv.indexOf('--segment') + 1])
  : null;
const concatOnly = process.argv.includes('--concat');

if (!apiKey && !concatOnly) {
  throw new Error('DEEPGRAM_API_KEY is required to generate Deepgram narration.');
}

const markdown = await readFile(scriptPath, 'utf8');
const lines = markdown
  .split(/\r?\n/)
  .filter((line) => line.startsWith('    '))
  .map((line) => line.trim())
  .filter(Boolean);

if (lines.length === 0) {
  throw new Error('SCRIPT.md contains no indented narration lines.');
}
if (requestedSegment !== null && (!Number.isInteger(requestedSegment) || requestedSegment < 1 || requestedSegment > lines.length)) {
  throw new Error(`--segment must be an integer between 1 and ${lines.length}.`);
}

await mkdir(outputDir, { recursive: true });
const partsDir = path.join(outputDir, 'deepgram-parts');
const concatPath = path.join(outputDir, 'deepgram-concat.txt');
await mkdir(partsDir, { recursive: true });

const selectedLines = requestedSegment === null
  ? lines.entries()
  : [[requestedSegment - 1, lines[requestedSegment - 1]]];
const partPaths = concatOnly
  ? lines.map((_, index) => path.join(partsDir, `${String(index + 1).padStart(2, '0')}.mp3`))
  : [];
for (const [index, line] of concatOnly ? [] : selectedLines) {
  const partName = `${String(index + 1).padStart(2, '0')}.mp3`;
  const partPath = path.join(partsDir, partName);
  const payloadPath = path.join(partsDir, `${String(index + 1).padStart(2, '0')}.json`);
  await writeFile(payloadPath, JSON.stringify({ text: line }));

  try {
    await execFileAsync('curl.exe', [
      '--silent',
      '--show-error',
      '--fail-with-body',
      '--connect-timeout',
      '10',
      '--max-time',
      '20',
      '--request',
      'POST',
      '--url',
      'https://api.deepgram.com/v1/speak?model=aura-2-thalia-en&encoding=mp3',
      '--header',
      `Authorization: Token ${apiKey}`,
      '--header',
      'Content-Type: application/json',
      '--data-binary',
      `@${payloadPath}`,
      '--output',
      partPath,
    ]);
  } catch (error) {
    const detail = String(error?.stderr ?? 'unknown curl error').trim();
    throw new Error(`Deepgram TTS segment ${index + 1} failed: ${detail}`);
  } finally {
    await rm(payloadPath, { force: true });
  }

  const part = await readFile(partPath);
  if (part.length < 1024) {
    throw new Error(`Deepgram TTS segment ${index + 1} returned an implausibly small audio payload.`);
  }
  partPaths.push(partPath);
}

if (requestedSegment !== null && !concatOnly) {
  console.log(`Deepgram narration segment ${requestedSegment} written: ${path.relative(projectRoot, partPaths[0])}`);
  process.exit(0);
}

await writeFile(
  concatPath,
  `${partPaths.map((partPath) => `file '${partPath.replaceAll("'", "'\\''")}'`).join('\n')}\n`,
);
try {
  await execFileAsync('ffmpeg', [
    '-y',
    '-f',
    'concat',
    '-safe',
    '0',
    '-i',
    concatPath,
    '-filter:a',
    'atempo=1.022',
    '-c:a',
    'libmp3lame',
    '-q:a',
    '2',
    outputPath,
  ]);
} finally {
  await rm(concatPath, { force: true });
}

const audio = await readFile(outputPath);
if (audio.length < 1024) {
  throw new Error('Deepgram TTS returned an implausibly small audio payload.');
}
await writeFile(
  metadataPath,
  `${JSON.stringify(
    {
      provider: 'deepgram',
      model: 'aura-2-thalia-en',
      encoding: 'mp3',
      script_sha256: await sha256(markdown),
      characters: lines.join(' ').length,
      words: lines.join(' ').split(/\s+/).length,
      segments: partPaths.length,
      postprocess: 'ffmpeg atempo=1.022 to fit the 90-second master',
      output: 'assets/audio/narration-deepgram.mp3',
    },
    null,
    2,
  )}\n`,
);

console.log(`Deepgram narration written: ${path.relative(projectRoot, outputPath)}`);

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Buffer.from(hash).toString('hex');
}
