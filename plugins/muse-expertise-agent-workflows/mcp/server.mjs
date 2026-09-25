#!/usr/bin/env node
import readline from 'node:readline';

const workflows = Object.freeze({
  earnie: Object.freeze({
    tool: 'expertise_earnie_vendor_value_review', skill: 'expertise-agent-workflows',
    title: 'Earnie — vendor value and renewal review',
    inputs: ['One exact playbook: renewal_vendor, quote_margin, collections, capacity_to_cash, or ai_spend.', 'Dated source records, integer metrics, and a named human approval owner.'],
    limits: ['Use only records supplied in this session or explicitly authorized files.', 'Missing required evidence blocks a recommendation.', 'Show conditional calculations; never claim realized savings.', 'No negotiation, payment, message, contract, approval, or external action.'],
  }),
  cluso: Object.freeze({
    tool: 'expertise_cluso_account_impact_review', skill: 'expertise-agent-workflows',
    title: 'Cluso — scoped account impact brief',
    inputs: ['Tenant, system, workspace, and account identity.', 'Explicit authorization, a bounded date window, and attributable source records.'],
    limits: ['Connected retrieval is unavailable unless a separately configured and approved connector returns data.', 'Separate confirmed, verify, and blocked statements.', 'No CRM writes, customer messages, or inferred account risk.'],
  }),
  surely: Object.freeze({
    tool: 'expertise_surely_portfolio_watch', skill: 'expertise-agent-workflows',
    title: 'Surely — commercial-site portfolio watch',
    inputs: ['Authorized U.S. commercial sites and review window.', 'Dated, attributable official-source event evidence and operator confirmation for impact claims.'],
    limits: ['Proximity is context, not proof of business impact.', 'Keep impact unknown without attributable operator confirmation.', 'No external messages or portfolio changes.', 'The prior Expertise MCP account_mismatch remains unresolved; never imply live connector success.'],
  }),
});

const tools = Object.freeze(Object.values(workflows).map((workflow) => ({
  name: workflow.tool,
  description: `Prepare the Muse agent to run ${workflow.title} using the installed workflow skill. This routes supplied context only; it does not connect to Expertise.ai or perform external actions.`,
  inputSchema: {
    type: 'object', additionalProperties: false, required: ['request'],
    properties: {
      request: { type: 'string', minLength: 1, maxLength: 4000, description: 'A concise user task or evidence summary. Do not include secrets.' },
      sourceRefs: { type: 'array', maxItems: 20, items: { type: 'string', maxLength: 260 }, description: 'Optional paths or record identifiers already supplied and authorized by the user.' },
    },
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
})));

function result(id, value) {
  return { jsonrpc: '2.0', id: id ?? null, result: value };
}

function error(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function handle(message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
    return error(message?.id, -32600, 'Invalid Request');
  }
  if (message.method.startsWith('notifications/')) return null;
  if (message.method === 'initialize') {
    return result(message.id, {
      protocolVersion: '2025-03-26', capabilities: { tools: {} },
      serverInfo: { name: 'expertise-agent-workflows', version: '0.1.0' },
    });
  }
  if (message.method === 'ping') return result(message.id, {});
  if (message.method === 'tools/list') return result(message.id, { tools });
  if (message.method !== 'tools/call') return error(message.id, -32601, 'Method not found');

  const params = message.params;
  if (!params || typeof params.name !== 'string' || !params.arguments || typeof params.arguments !== 'object' || Array.isArray(params.arguments)) {
    return error(message.id, -32602, 'Invalid params');
  }
  const workflow = Object.values(workflows).find((item) => item.tool === params.name);
  if (!workflow) return result(message.id, { content: [{ type: 'text', text: 'unknown_tool' }], isError: true });

  const args = params.arguments;
  if (Object.keys(args).some((key) => !['request', 'sourceRefs'].includes(key)) ||
      typeof args.request !== 'string' || args.request.trim() !== args.request || args.request.length < 1 || args.request.length > 4000 ||
      (args.sourceRefs !== undefined && (!Array.isArray(args.sourceRefs) || args.sourceRefs.length > 20 || args.sourceRefs.some((ref) => typeof ref !== 'string' || ref.length > 260 || ref.trim() !== ref)))) {
    return result(message.id, { content: [{ type: 'text', text: 'invalid_workflow_request' }], isError: true });
  }

  const packet = {
    schemaVersion: 'expertise.muse-workflow.v1',
    status: 'prepared_for_muse_review',
    workflow: params.name,
    skillId: workflow.skill,
    title: workflow.title,
    request: args.request,
    sourceRefs: args.sourceRefs || [],
    requiredInputs: workflow.inputs,
    boundaries: workflow.limits,
    execution: 'Muse agent performs an advisory review from authorized supplied context; this MCP tool does not fetch data or call Expertise.ai.',
  };
  return result(message.id, { content: [{ type: 'text', text: JSON.stringify(packet) }], structuredContent: packet, isError: false });
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
input.on('line', (line) => {
  if (Buffer.byteLength(line, 'utf8') > 32_768) return;
  let message;
  try { message = JSON.parse(line); } catch { return; }
  const response = handle(message);
  if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
});
