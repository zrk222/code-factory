import * as assert from "node:assert/strict";
import { escapeHtml, receiptHtml, summarizeReceipt } from "../receipt";
import { factoryExecutable, isFeatureName } from "../runner";
import { meterHtml } from "../meter";

const receipt = {
  schema: "factory.trace.v1",
  feature: "editor-layer",
  rollup: { verdict: "SHIPPABLE" },
  stage: "evidence",
};

assert.deepEqual(summarizeReceipt(receipt), {
  schema: "factory.trace.v1",
  feature: "editor-layer",
  verdict: "SHIPPABLE",
  stage: "evidence",
});
assert.equal(escapeHtml(`<receipt & "proof">`), "&lt;receipt &amp; &quot;proof&quot;&gt;");
assert.match(receiptHtml(receipt, "receipt <panel>"), /receipt &lt;panel&gt;/);
assert.match(receiptHtml(receipt, "receipt"), /SHIPPABLE/);
assert.equal(factoryExecutable("factory", "win32"), "factory.exe");
assert.equal(factoryExecutable("C:\\tools\\factory.exe", "win32"), "C:\\tools\\factory.exe");
assert.equal(factoryExecutable("factory", "linux"), "factory");
assert.match(meterHtml({ summary: { stages_measured: 2, build_wall_ms: 10, tokens_reported_by_modules: false }, activity: { stages_successful: 2, latest_stage: { module: "hsf", stage: "compile", ok: true } } }), /not reported by modules/);
assert.equal(isFeatureName("editor-layer_1"), true);
assert.equal(isFeatureName("editor layer; rm"), false);
