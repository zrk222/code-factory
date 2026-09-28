import { build } from "esbuild";
await build({ entryPoints: ["src/extension.ts"], bundle: true, platform: "node", target: "node18", format: "cjs", external: ["vscode"], outfile: "dist/extension.js", sourcemap: false });
