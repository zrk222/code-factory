const target = process.env.AGENT_OVEN_LOAD_URL;
if (!target) {
  console.error("AGENT_OVEN_LOAD_URL is required; load tests never default to production.");
  process.exit(1);
}
const url = new URL(target);
if (url.protocol !== "https:" || !/^(staging|load|perf)[.-]/i.test(url.hostname)) {
  console.error("Load target must be an explicit HTTPS staging/load/perf host.");
  process.exit(1);
}
const concurrency = Number(process.env.AGENT_OVEN_LOAD_CONCURRENCY ?? 10);
const requests = Number(process.env.AGENT_OVEN_LOAD_REQUESTS ?? 100);
if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 100 || !Number.isInteger(requests) || requests < 1 || requests > 10000) process.exit(1);
const latencies = [];
let next = 0;
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (next < requests) {
    next += 1;
    const start = performance.now();
    const response = await fetch(url, { redirect: "error" });
    latencies.push(performance.now() - start);
    if (!response.ok) throw new Error(`LOAD_REQUEST_FAILED_${response.status}`);
  }
}));
latencies.sort((a, b) => a - b);
const percentile = (p) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))];
console.log(JSON.stringify({ marker: "LOAD_TEST_COMPLETE", requests: latencies.length, concurrency, p50Ms: Math.round(percentile(.5)), p95Ms: Math.round(percentile(.95)), p99Ms: Math.round(percentile(.99)) }));
