// Length-preserving rewrites for syntax the pinned scanner cannot parse.
//
// Each rewrite keeps every byte offset, line and column, so alerts on the rewritten copy map
// back to the original without translation. A rewrite is admitted only when the original is
// valid source the parser rejects and the replacement is valid source with the same tokens
// for analysis purposes. Every edit is recorded so a receipt can show exactly which bytes of
// a scanned copy differ from the source tree.
//
// Usage: node scripts/syntax_compat.mjs stage --source DIR --out DIR --receipt FILE
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx']);

export const REWRITES = [
  {
    id: 'js-ternary-leading-dot-number',
    // `c?.5:0` is a conditional whose consequent is `.5`; ECMAScript forbids reading `?.`
    // as optional chaining when a decimal digit follows. OpenGrep 2.0.0 tokenizes it as
    // `?.` and fails (seen in minified bundles). `? 5` keeps length and stays a number.
    extensions: JS_EXTENSIONS,
    pattern: /\?\.(?=\d)/g,
    replacement: '? ',
  },
];

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export function rewrite(text, extension) {
  let output = text;
  const edits = [];
  for (const rule of REWRITES) {
    if (!rule.extensions.has(extension)) continue;
    output = output.replace(rule.pattern, (match, offset) => {
      if (rule.replacement.length !== match.length) throw new Error(`Rewrite ${rule.id} changes length`);
      edits.push({ rule: rule.id, offset, from: match, to: rule.replacement });
      return rule.replacement;
    });
  }
  if (output.length !== text.length) throw new Error('Rewrite changed the text length');
  for (const edit of edits) {
    const before = text.slice(0, edit.offset);
    edit.line = before.split('\n').length;
    edit.column = edit.offset - before.lastIndexOf('\n');
  }
  return { text: output, edits };
}

function* walk(root, directory = root) {
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    const info = lstatSync(path);
    if (info.isSymbolicLink() || (info.isDirectory() && name === '.git')) continue;
    if (info.isDirectory()) yield* walk(root, path);
    else if (info.isFile()) yield path;
  }
}

export function stage(source, out) {
  const files = [];
  for (const path of walk(source)) {
    const rel = relative(source, path);
    const bytes = readFileSync(path);
    const target = join(out, rel);
    mkdirSync(join(target, '..'), { recursive: true });
    let written = bytes, edits = [];
    if (JS_EXTENSIONS.has(extname(path))) {
      const text = bytes.toString('utf8');
      if (Buffer.from(text, 'utf8').equals(bytes)) {
        const result = rewrite(text, extname(path));
        if (result.edits.length) {
          written = Buffer.from(result.text, 'utf8');
          if (written.length !== bytes.length) throw new Error(`Byte length changed for ${rel}`);
          edits = result.edits;
        }
      }
    }
    writeFileSync(target, written);
    if (edits.length) {
      files.push({ path: rel, source_sha256: sha256(bytes), staged_sha256: sha256(written), edits });
    }
  }
  return files;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, ...rest] = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < rest.length; i += 2) opts[rest[i].replace(/^--/, '')] = rest[i + 1];
  if (command !== 'stage' || !opts.source || !opts.out || !opts.receipt) {
    console.error('usage: syntax_compat.mjs stage --source DIR --out DIR --receipt FILE');
    process.exit(2);
  }
  const files = stage(opts.source, opts.out);
  const receipt = {
    schema: 'factory.syntax-compat-stage.v1',
    rewrites: REWRITES.map(rule => ({ id: rule.id, pattern: String(rule.pattern), replacement: rule.replacement })),
    rewritten_files: files,
  };
  writeFileSync(opts.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(JSON.stringify({ rewritten_files: files.length, edits: files.reduce((n, f) => n + f.edits.length, 0) }));
}
