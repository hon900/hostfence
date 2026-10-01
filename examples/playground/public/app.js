const $ = selector => document.querySelector(selector);
const form = $('#check-form');
const input = $('#url');
const profile = $('#profile');
let scenarios = [];
let profiles = {};
let lastResult;
let inspection = 0;

async function check(url, policy = 'default') {
  const response = await fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, profile: policy }) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error ?? 'Inspection failed.');
  return result;
}

function render(result) {
  lastResult = result;
  $('#verdict').textContent = result.ok ? 'Allowed' : 'Blocked';
  $('#verdict').className = `verdict ${result.ok ? 'allowed' : 'blocked'}`;
  $('#decision-detail').textContent = result.ok ? 'Every resolved address passed the selected policy.' : result.reasons.join(' · ');
  $('#elapsed').textContent = `${result.durationMs.toFixed(2)} ms`;
  $('#result-host').textContent = result.hostname || 'Invalid URL';
  $('#result-source').textContent = 'Offline fixtures / IP literals';
  const addresses = $('#addresses');
  addresses.replaceChildren();
  if (!result.classifications.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No addresses returned. See the verdict for details.';
    addresses.append(empty);
  }
  for (const { address, kind } of result.classifications) {
    const row = document.createElement('div');
    row.className = 'address';
    const ip = document.createElement('code');
    ip.textContent = address;
    const label = document.createElement('span');
    label.textContent = kind;
    row.append(ip, label);
    addresses.append(row);
  }
  $('#json-result').textContent = JSON.stringify(result, null, 2);
  $('#copy-button').disabled = false;
}

async function inspect() {
  const id = ++inspection;
  $('#check-button').disabled = true;
  $('#check-button').textContent = 'Inspecting…';
  $('#result-pane').setAttribute('aria-busy', 'true');
  $('#form-error').hidden = true;
  try {
    const result = await check(input.value.trim(), profile.value);
    if (id === inspection) render(result);
  } catch (error) {
    if (id !== inspection) return;
    $('#form-error').textContent = `${error.message} Check that the local server is running and try again.`;
    $('#form-error').hidden = false;
    $('#verdict').textContent = 'Unavailable';
    $('#verdict').className = 'verdict empty';
    $('#decision-detail').textContent = 'No inspection result was received.';
    $('#elapsed').textContent = '';
    $('#result-host').textContent = 'Not inspected';
    $('#addresses').replaceChildren();
    $('#json-result').textContent = 'No inspection result was received.';
    $('#copy-button').disabled = true;
    lastResult = undefined;
  } finally {
    if (id === inspection) {
      $('#check-button').disabled = false;
      $('#check-button').textContent = 'Inspect URL ↗';
      $('#result-pane').setAttribute('aria-busy', 'false');
    }
  }
}

function selectScenario(scenario) {
  input.value = scenario.url;
  for (const button of document.querySelectorAll('[data-scenario]')) button.setAttribute('aria-pressed', String(button.dataset.scenario === scenario.id));
  inspect();
}

form.addEventListener('submit', event => { event.preventDefault(); inspect(); });
input.addEventListener('input', () => { for (const button of document.querySelectorAll('[data-scenario]')) button.setAttribute('aria-pressed', 'false'); });
profile.addEventListener('change', () => { $('#policy-description').textContent = profiles[profile.value]?.description ?? ''; inspect(); });
for (const button of document.querySelectorAll('[data-scenario]')) {
  button.addEventListener('click', () => { const scenario = scenarios.find(item => item.id === button.dataset.scenario); if (scenario) selectScenario(scenario); });
}

$('#copy-button').addEventListener('click', async () => {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    $('#copy-button').textContent = 'Copied';
  } catch { $('#copy-button').textContent = 'Select and copy the JSON above'; }
  setTimeout(() => { $('#copy-button').textContent = 'Copy JSON'; }, 2000);
});

$('#run-suite').addEventListener('click', async () => {
  const button = $('#run-suite');
  button.disabled = true;
  button.textContent = 'Running scenarios…';
  let passed = 0;
  let failed = 0;
  let unavailable = 0;
  for (const scenario of scenarios) {
    const status = document.querySelector(`[data-status="${scenario.id}"]`);
    status.textContent = 'Checking…';
    status.className = 'scenario-status';
    try {
      const result = await check(scenario.url);
      const matches = result.ok === scenario.expected;
      if (matches) passed++; else failed++;
      status.textContent = matches ? 'PASS' : 'MISMATCH';
      status.className = `scenario-status ${matches ? 'pass' : 'fail'}`;
    } catch {
      unavailable++;
      status.textContent = 'UNAVAILABLE';
      status.className = 'scenario-status fail';
    }
    $('#suite-summary').textContent = `${passed + failed + unavailable} / ${scenarios.length} checked with the default policy.`;
  }
  $('#suite-summary').textContent = `${passed} / ${scenarios.length} matched expectations · ${failed} mismatches · ${unavailable} unavailable · default policy, offline fixtures.`;
  button.disabled = false;
  button.textContent = 'Run all scenarios';
});

async function init() {
  try {
    const response = await fetch('/api/scenarios');
    if (!response.ok) throw new Error('Could not load scenarios.');
    ({ scenarios, profiles } = await response.json());
    const list = $('#scenario-list');
    list.replaceChildren();
    for (const scenario of scenarios) {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'scenario';
      row.title = scenario.detail;
      row.setAttribute('aria-label', `Inspect ${scenario.name}: ${scenario.url}`);
      for (const [className, text] of [['scenario-name', scenario.name], ['scenario-url', scenario.url], ['scenario-category', scenario.category], ['scenario-status', 'Inspect ↗']]) {
        const cell = document.createElement('span');
        cell.className = className;
        cell.textContent = text;
        if (className === 'scenario-status') cell.dataset.status = scenario.id;
        row.append(cell);
      }
      row.addEventListener('click', () => { selectScenario(scenario); $('#playground').scrollIntoView({ block: 'start' }); });
      list.append(row);
    }
    await inspect();
  } catch {
    $('#scenario-list').textContent = 'Scenarios could not be loaded. Restart the local server and reload this page.';
    $('#run-suite').disabled = true;
    $('#form-error').textContent = 'The playground could not connect to its local server.';
    $('#form-error').hidden = false;
  }
}
init();
