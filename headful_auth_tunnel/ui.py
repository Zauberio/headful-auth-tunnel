LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Headful Auth Tunnel</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body class="login-page">
  <main class="login-card">
    <h1>Headful Auth Tunnel</h1>
    <p>Enter the token stored in the configured token file.</p>
    <form method="post" action="/session">
      <label for="token">Access token</label>
      <input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Open tunnel</button>
    </form>
  </main>
</body>
</html>
"""

APP_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Headful Auth Tunnel</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <header>
    <div>
      <h1>Headful Auth Tunnel</h1>
      <span id="status">connecting</span>
    </div>
    <form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form>
  </header>

  <main>
    <section class="toolbar">
      <div class="row grow">
        <button id="back" class="secondary" title="Back">←</button>
        <button id="forward" class="secondary" title="Forward">→</button>
        <button id="reload" class="secondary" title="Reload">↻</button>
        <input id="url" class="grow" type="url" placeholder="https://example.com">
        <button id="go">Go</button>
      </div>
      <div class="row">
        <label>Tab <select id="tabs"></select></label>
        <button id="focusTab" class="secondary">Focus</button>
        <button id="closeTab" class="secondary">Close</button>
        <label>Viewport <input id="width" class="small" type="number" min="320" max="7680"> × <input id="height" class="small" type="number" min="240" max="4320"></label>
        <button id="resize" class="secondary">Apply</button>
      </div>
      <div class="row">
        <input id="text" class="grow" type="text" placeholder="Text to type into the focused field">
        <button id="type">Send</button>
        <input id="key" class="medium" type="text" placeholder="Key, e.g. Enter">
        <button id="press" class="secondary">Press</button>
        <button id="refresh" class="secondary">Refresh image</button>
      </div>
    </section>

    <section class="viewer">
      <img id="screen" alt="Browser screenshot" draggable="false">
      <div id="coords">Click or drag directly on the screenshot.</div>
    </section>

    <section class="panels">
      <article>
        <h2>DOM controls</h2>
        <div class="stack">
          <input id="selector" type="text" placeholder="CSS selector">
          <input id="value" type="text" placeholder="Value">
          <div class="row">
            <button id="fill">Fill</button>
            <button id="clickSelector" class="secondary">Click selector</button>
            <button id="snapshot" class="secondary">Read page</button>
          </div>
          <div class="row">
            <label class="check"><input id="includeValues" type="checkbox" checked> Include field values</label>
            <label class="check"><input id="includeSensitiveValues" type="checkbox"> Reveal password, token and OTP values</label>
          </div>
        </div>
      </article>
      <article>
        <h2>Page snapshot</h2>
        <pre id="page">No snapshot loaded.</pre>
      </article>
    </section>
  </main>
  <script src="/app.js" defer></script>
</body>
</html>
"""

APP_CSS = r"""
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b0d10; color: #f4f7fb; }
header { position: sticky; top: 0; z-index: 5; display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: .8rem 1rem; background: rgba(11,13,16,.94); border-bottom: 1px solid #252b33; backdrop-filter: blur(10px); }
h1 { margin: 0; font-size: 1rem; }
h2 { margin: 0 0 .7rem; font-size: .95rem; }
#status { font-size: .75rem; color: #8fa1b6; }
main { padding: 1rem; display: grid; gap: 1rem; }
.toolbar, .viewer, article, .login-card { border: 1px solid #252b33; background: #12161b; border-radius: 12px; }
.toolbar { padding: .8rem; display: grid; gap: .65rem; }
.row { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
.stack { display: grid; gap: .55rem; }
.grow { flex: 1 1 20rem; }
.small { width: 6rem; }
.medium { width: 10rem; }
input, select, button { min-height: 2.25rem; border-radius: 8px; border: 1px solid #35404d; font: inherit; }
input, select { padding: .45rem .65rem; background: #0b0f14; color: #f4f7fb; }
button { padding: .45rem .8rem; background: #2d6cdf; color: white; cursor: pointer; }
button.secondary { background: #1a2028; }
button:disabled { opacity: .5; cursor: default; }
label { display: flex; align-items: center; gap: .4rem; font-size: .8rem; color: #b7c2cf; }
.check input { min-height: auto; width: auto; }
.viewer { overflow: hidden; }
#screen { display: block; width: 100%; height: auto; background: #050607; cursor: crosshair; user-select: none; }
#coords { padding: .45rem .7rem; color: #8fa1b6; font-size: .75rem; border-top: 1px solid #252b33; }
.panels { display: grid; grid-template-columns: minmax(18rem, .7fr) minmax(20rem, 1.3fr); gap: 1rem; }
article { padding: .8rem; min-width: 0; }
pre { margin: 0; min-height: 9rem; max-height: 28rem; overflow: auto; white-space: pre-wrap; word-break: break-word; color: #cbd6e2; font-size: .76rem; }
.login-page { min-height: 100vh; display: grid; place-items: center; padding: 1rem; }
.login-card { width: min(28rem, 100%); padding: 1.2rem; }
.login-card p { color: #aab6c4; }
.login-card form { display: grid; gap: .7rem; }
.login-card label { display: block; }
@media (max-width: 850px) { .panels { grid-template-columns: 1fr; } }
"""

APP_JS = r"""
const $ = (id) => document.getElementById(id);
let refreshTimer = null;
let dragStart = null;
let screenshotBusy = false;

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...options,
    headers: {'Content-Type': 'application/json', ...(options.headers || {})}
  });
  if (response.status === 401) { location.href = '/'; throw new Error('Authentication expired'); }
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(payload.error || payload || `HTTP ${response.status}`);
  return payload;
}

function body(value) { return JSON.stringify(value); }
function setStatus(message, error = false) {
  $('status').textContent = message;
  $('status').style.color = error ? '#ff8585' : '#8fa1b6';
}

async function refreshMeta() {
  const meta = await api('/meta');
  $('url').value = meta.url || '';
  $('width').value = meta.viewport.width;
  $('height').value = meta.viewport.height;
  clearInterval(refreshTimer);
  refreshTimer = setInterval(refreshScreenshot, meta.screenshot_interval_ms);
  await refreshTabs();
}

async function refreshTabs() {
  const data = await api('/tabs');
  const select = $('tabs');
  const selected = select.value;
  select.replaceChildren();
  for (const tab of data.tabs) {
    const option = document.createElement('option');
    option.value = tab.id;
    option.textContent = `${tab.active ? '● ' : ''}${tab.title || '(untitled)'} — ${tab.url}`;
    option.selected = tab.id === selected || tab.active;
    select.appendChild(option);
  }
}

async function refreshScreenshot() {
  if (screenshotBusy) return;
  screenshotBusy = true;
  try {
    const response = await fetch(`/screenshot?t=${Date.now()}`, {credentials: 'same-origin', cache: 'no-store'});
    if (response.status === 401) { location.href = '/'; return; }
    if (!response.ok) throw new Error(`Screenshot HTTP ${response.status}`);
    const blob = await response.blob();
    const next = URL.createObjectURL(blob);
    const previous = $('screen').src;
    $('screen').src = next;
    if (previous.startsWith('blob:')) URL.revokeObjectURL(previous);
    setStatus('connected');
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    screenshotBusy = false;
  }
}

function imagePoint(event) {
  const image = $('screen');
  const rect = image.getBoundingClientRect();
  return {
    x: Math.round((event.clientX - rect.left) * image.naturalWidth / rect.width),
    y: Math.round((event.clientY - rect.top) * image.naturalHeight / rect.height)
  };
}

$('screen').addEventListener('mousedown', (event) => { dragStart = imagePoint(event); });
$('screen').addEventListener('mouseup', async (event) => {
  if (!dragStart) return;
  const end = imagePoint(event);
  const distance = Math.hypot(end.x - dragStart.x, end.y - dragStart.y);
  $('coords').textContent = `${end.x}, ${end.y}`;
  try {
    if (distance < 8) await api('/click', {method: 'POST', body: body(end)});
    else await api('/drag', {method: 'POST', body: body({from: dragStart, to: end, duration_ms: 500})});
    await refreshScreenshot();
  } catch (error) { setStatus(error.message, true); }
  dragStart = null;
});

$('go').addEventListener('click', async () => {
  try { await api('/navigate', {method: 'POST', body: body({url: $('url').value})}); await refreshMeta(); await refreshScreenshot(); }
  catch (error) { setStatus(error.message, true); }
});
$('url').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('go').click(); });
$('back').addEventListener('click', async () => { try { await api('/history/back', {method: 'POST', body: '{}'}); await refreshMeta(); } catch (e) { setStatus(e.message, true); } });
$('forward').addEventListener('click', async () => { try { await api('/history/forward', {method: 'POST', body: '{}'}); await refreshMeta(); } catch (e) { setStatus(e.message, true); } });
$('reload').addEventListener('click', async () => { try { await api('/reload', {method: 'POST', body: '{}'}); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('refresh').addEventListener('click', refreshScreenshot);
$('type').addEventListener('click', async () => { try { await api('/type', {method: 'POST', body: body({text: $('text').value})}); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('press').addEventListener('click', async () => { try { await api('/key', {method: 'POST', body: body({key: $('key').value})}); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('resize').addEventListener('click', async () => { try { await api('/viewport', {method: 'POST', body: body({width: Number($('width').value), height: Number($('height').value)})}); await refreshMeta(); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('focusTab').addEventListener('click', async () => { try { await api('/tabs/focus', {method: 'POST', body: body({id: $('tabs').value})}); await refreshMeta(); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('closeTab').addEventListener('click', async () => { try { await api('/tabs/close', {method: 'POST', body: body({id: $('tabs').value})}); await refreshMeta(); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('fill').addEventListener('click', async () => { try { await api('/dom/fill', {method: 'POST', body: body({selector: $('selector').value, value: $('value').value})}); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('clickSelector').addEventListener('click', async () => { try { await api('/dom/click', {method: 'POST', body: body({selector: $('selector').value})}); await refreshScreenshot(); } catch (e) { setStatus(e.message, true); } });
$('snapshot').addEventListener('click', async () => {
  try {
    const payload = {
      include_values: $('includeValues').checked,
      include_sensitive_values: $('includeSensitiveValues').checked
    };
    $('page').textContent = JSON.stringify(
      await api('/page', {method: 'POST', body: body(payload)}),
      null,
      2
    );
  } catch (e) { setStatus(e.message, true); }
});

window.addEventListener('load', async () => {
  try { await refreshMeta(); await refreshScreenshot(); setStatus('connected'); }
  catch (error) { setStatus(error.message, true); }
});
"""
