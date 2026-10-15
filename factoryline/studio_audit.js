(function () {
  const grid = document.querySelector('#dashboard .dash-grid');
  if (!grid) return;
  const panel = document.createElement('section');
  panel.id = 'studio-audit-panel'; panel.className = 'panel wide-panel';
  panel.setAttribute('aria-labelledby', 'studio-audit-title');
  const title = document.createElement('h2');
  title.id = 'studio-audit-title';
  title.textContent = 'Audit findings';
  panel.appendChild(title);
  grid.prepend(panel);
  const status = document.createElement('div');
  status.setAttribute('role', 'status');
  const proposalHost = document.createElement('div');
  panel.append(status, proposalHost);
  let current = null;
  async function request(path, method = 'GET', body) {
    const options = { headers: { 'X-Factory-Studio-Token': token } };
    if (method !== 'GET') {
      options.method = method;
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.code + ': ' + data.message);
    return data;
  }
  function line(parent, label, value) {
    const row = document.createElement('p');
    row.className = 'empty-data';
    row.textContent = label + ': ' + (value ?? 'not available');
    parent.appendChild(row);
  }
  async function refresh() {
    try {
      const next = await request('/api/studio-audit');
      if (JSON.stringify(next) === JSON.stringify(current)) return;
      current = next;
      status.textContent = '';
      line(status, 'Projection', current.state);
      line(status, 'Observed state', current.observed_state);
      if (current.run_id) line(status, 'Run', current.run_id);
      if (current.candidate_sha256) line(status, 'Candidate SHA-256', current.candidate_sha256);
      if (current.truncated) line(status, 'Notice', 'Findings are truncated to the first 20. Select only findings shown here.');
      const list = document.createElement('fieldset');
      const legend = document.createElement('legend');
      legend.textContent = 'Select findings for a sealed proposal';
      list.appendChild(legend);
      (current.repair_tasks || []).forEach((finding) => {
        const label = document.createElement('label');
        label.className = 'data-row';
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.value = finding.finding_id;
        box.setAttribute('aria-label', finding.severity + ' ' + finding.rule_id + ' at ' + finding.path);
        const text = document.createElement('span');
        text.textContent = finding.severity + ' · ' + finding.rule_id + ' · ' + finding.path + (finding.line ? ':' + finding.line : '') + ' — ' + finding.remediation;
        label.append(box, text);
        list.appendChild(label);
      });
      status.appendChild(list);
      if (!(current.repair_tasks || []).length) line(status, 'Findings', 'No findings are available in this projection.');
      const actions = document.createElement('div');
      actions.className = 'decision-bar';
      const prepare = document.createElement('button');
      prepare.type = 'button';
      prepare.textContent = 'Prepare sealed proposal';
      const active = ['RUNNING', 'PAUSE_REQUESTED'].includes(current.observed_state);
      const selectionChanged = () => {
        prepare.disabled = active || !current.run_id || !current.state_content_sha256 ||
          !list.querySelector('input:checked');
      };
      list.addEventListener('change', selectionChanged);
      selectionChanged();
      prepare.onclick = async () => {
        const finding_ids = Array.from(list.querySelectorAll('input:checked')).map((box) => box.value);
        if (!finding_ids.length) { line(status, 'Selection', 'Select at least one finding first.'); return; }
        prepare.disabled = true;
        try {
          const result = await request('/api/studio-audit/prepare', 'POST', {
            run_id: current.run_id,
            expected_state_content_sha256: current.state_content_sha256,
            finding_ids
          });
          const proposal = document.createElement('div');
          line(proposal, 'Sealed proposal', result.scope_id);
          result.finding_ids.forEach((id) => line(proposal, 'Selected finding', id));
          Object.entries(result.paths).forEach(([kind, path]) => line(proposal, kind + ' artifact', path));
          line(proposal, 'Authority', 'Sealed proposal only; no candidate execution or approval.');
          line(proposal, 'Next action', 'Review, then use the existing repair candidate and exact approval workflow separately.');
          proposalHost.replaceChildren(proposal);
        } catch (error) { line(status, 'Proposal unavailable', error.message); }
        finally { prepare.disabled = false; }
      };
      actions.appendChild(prepare);
      if (current.observed_state === 'RUNNING') {
        const pause = document.createElement('button');
        pause.type = 'button';
        pause.textContent = 'Request audit pause';
        pause.onclick = async () => {
          pause.disabled = true;
          try {
            const result = await request('/api/studio-audit/pause', 'POST', {
              run_id: current.run_id,
              expected_state_content_sha256: current.state_content_sha256
            });
            line(status, 'Pause request', result.state === 'PAUSE_REQUESTED' ? 'PAUSE_REQUESTED — waiting for the runner to stop.' : result.state);
            await refresh();
          } catch (error) { line(status, 'Pause unavailable', error.message); }
        };
        actions.appendChild(pause);
      }
      status.appendChild(actions);
      if (current.observed_state === 'PAUSE_REQUESTED') line(status, 'Audit status', 'Pause requested; this does not mean the audit is paused yet.');
    } catch (error) { current = null; status.textContent = 'Audit projection unavailable: ' + error.message; }
  }
  refresh();
  window.setInterval(refresh, 10000);
})();
