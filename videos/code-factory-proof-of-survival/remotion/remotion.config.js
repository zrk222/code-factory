import { execFileSync } from 'node:child_process';

execFileSync(process.execPath, ['src/stage-assets.mjs'], { stdio: 'inherit', windowsHide: true });
