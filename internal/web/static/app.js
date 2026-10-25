// Панель ServerSecurityGo.
//
// Безопасность: имена процессов, командные строки и пути контролирует
// потенциальный злоумышленник, поэтому весь вывод идёт через
// textContent (функция h ниже). innerHTML не используется нигде.
'use strict';

// ---------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------

// Невидимые символы форматирования (см. model.InvisibleRune): «справа
// налево» U+202E и символы нулевой ширины позволили бы процессу показать в
// панели не ту команду, что он выполняет. Заменяются видимым «�».
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u061C]/g;
const vis = (s) => String(s).replace(INVISIBLE, '\uFFFD');

/** Создаёт DOM-элемент. attrs: class, title, data-*, обработчики on*. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
      else el.setAttribute(k, v === true ? '' : vis(v));
    }
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(vis(c)));
  }
  return el;
}

const $ = (id) => document.getElementById(id);
const RISKS = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const riskNum = (r) => RISKS.indexOf(r);
const riskBadge = (r) => h('span', { class: 'risk risk-' + r }, r);

// Названия типов событий и категорий признаков — из общего каталога
// (event.<тип>, cat.<категория>), неизвестное значение выводится как есть.
const EVENT_TYPES = ['baseline', 'started', 'exited', 'changed', 'risk_up', 'risk_down', 'finding', 'listen', 'system'];
const CATEGORIES = ['location', 'integrity', 'masquerade', 'chain', 'network', 'content', 'behavior', 'environment', 'privilege', 'persistence', 'exposure', 'info'];
const eventName = (t) => (EVENT_TYPES.includes(t) ? tr('event.' + t) : t);

// Подписи доступности порта, состояния ufw и межсетевого экрана для порта.
// Явные вызовы tr('…'), а не склейка ключа: keys_test сверяет их с каталогом.
const SCOPE_NAMES = {
  public: () => tr('tui.scope.public'), private: () => tr('tui.scope.private'),
  loopback: () => tr('tui.scope.loopback'), netns: () => tr('tui.scope.netns'),
};
const FW_NAMES = {
  open: () => tr('tui.fw.open'), filtered: () => tr('tui.fw.filtered'), bypassed: () => tr('tui.fw.bypassed'),
};
const UFW_NAMES = {
  absent: () => tr('tui.ufw.absent'), inactive: () => tr('tui.ufw.inactive'), active: () => tr('tui.ufw.active'),
};
const label = (names, v) => (names[v] ? names[v]() : (v || '—'));
const endpoint = (addr, port) => (addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`);
const categoryName = (c) => (CATEGORIES.includes(c) ? tr('cat.' + c) : c);

function fmtBytes(n) {
  if (!n) return '0';
  const u = tr('web.units').split(',');
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}
function fmtTime(t) {
  if (!t || t.startsWith('0001')) return '—';
  return new Date(t).toLocaleString(dateLocale());
}
function fmtAgo(t) {
  if (!t || t.startsWith('0001')) return '—';
  let s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const hh = Math.floor(s / 3600); s -= hh * 3600;
  const m = Math.floor(s / 60);
  if (d > 0) return tr('tui.ago.days', d, hh);
  if (hh > 0) return tr('tui.ago.hours', hh, m);
  if (m > 0) return tr('tui.ago.minutes', m);
  return tr('tui.ago.seconds', Math.floor(s));
}
function fmtPct(v) { return (v || 0).toFixed(1); }

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add('hidden'), 1800);
}

/** Копирует текст в буфер обмена (с запасным вариантом для старых браузеров). */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = h('textarea', { class: 'offscreen' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(tr('web.copied'));
}

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

const state = {
  csrf: '', status: null, processes: [], sockets: [], events: [], system: null, tree: null, exposure: null,
  tab: 'suspicious', sort: {}, showAll: {}, collapsed: new Set(), treeExpandedAll: false,
};

async function api(path, opts = {}) {
  const headers = { 'Accept': 'application/json', 'X-SSG-Lang': I18N.lang };
  if (opts.method && opts.method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
  const r = await fetch(path, { credentials: 'same-origin', ...opts, headers });
  if (r.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

// ---------------------------------------------------------------------
// Таблицы
// ---------------------------------------------------------------------

const PAGE = 400; // строк до кнопки «показать все»

/**
 * Рисует таблицу. cols: [{t: заголовок, v: (row)=>значение для сортировки,
 * r: (row)=>содержимое ячейки, c: класс ячейки}]. Сортировка по клику.
 */
function renderTable(id, cols, rows, onClick, emptyText) {
  const table = $(id);
  const sort = state.sort[id] || { col: -1, dir: 1 };
  if (sort.col >= 0 && cols[sort.col]) {
    const v = cols[sort.col].v;
    rows = rows.slice().sort((a, b) => {
      const x = v(a), y = v(b);
      return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
    });
  }
  const head = h('tr', null, cols.map((c, i) => h('th', {
    class: i === sort.col ? 'sorted' : '',
    title: tr('web.sort'),
    onclick: () => {
      state.sort[id] = { col: i, dir: sort.col === i ? -sort.dir : (c.desc ? -1 : 1) };
      renderAll();
    },
  }, c.t, i === sort.col ? (sort.dir > 0 ? ' ▲' : ' ▼') : '')));
  const limit = state.showAll[id] ? rows.length : PAGE;
  const body = h('tbody');
  for (const row of rows.slice(0, limit)) {
    body.append(h('tr', { onclick: onClick ? () => onClick(row) : null }, cols.map((c) => h('td', { class: c.c || '' }, c.r(row)))));
  }
  table.replaceChildren(h('thead', null, head), body);
  const wrap = table.parentElement;
  wrap.querySelectorAll('.empty,.more').forEach((e) => e.remove());
  if (rows.length === 0) wrap.append(h('div', { class: 'empty' }, emptyText || tr('web.no_data')));
  if (rows.length > limit) {
    wrap.append(h('div', { class: 'more' }, tr('web.shown', limit, rows.length) + ' ',
      h('button', { class: 'small secondary', type: 'button', onclick: () => { state.showAll[id] = true; renderAll(); } }, tr('web.show_all'))));
  }
}

function findingTags(p) {
  return h('div', null, p.findings.map((f) => h('span', {
    class: 'tag' + (f.strong ? ' strong' : '') + (f.suppressed ? ' supp' : ''),
    title: tr('web.tag_title', categoryName(f.category), f.weight) + (f.suppressed ? ', ' + tr('tui.suppressed') : ''),
  }, tx(f.title))));
}

// Значения фильтров процессов.
function procFilter() {
  const q = $('f-q').value.trim().toLowerCase();
  const pid = $('f-pid').value.trim();
  const user = $('f-user').value.trim().toLowerCase();
  const name = $('f-name').value.trim().toLowerCase();
  const path = $('f-path').value.trim().toLowerCase();
  const risk = $('f-risk').value;
  const kernel = $('f-kernel').checked;
  return (p) => {
    if (!kernel && p.kernel) return false;
    if (pid && String(p.pid) !== pid && String(p.ppid) !== pid) return false;
    if (user && !p.user.toLowerCase().includes(user)) return false;
    if (name && !p.name.toLowerCase().includes(name)) return false;
    if (path && !(p.exe || '').toLowerCase().includes(path)) return false;
    if (risk && riskNum(p.risk) < riskNum(risk)) return false;
    if (q) {
      const hay = [p.pid, p.name, p.user, p.exe, p.cmdline, p.container, ...p.findings.map((f) => tx(f.title))].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  };
}

// Колонки таблиц процессов. Заголовки — функции: язык можно переключить на лету.
const colPID = () => ({ t: 'PID', v: (p) => p.pid, r: (p) => p.pid, c: 'num' });
const colName = () => ({ t: tr('tui.k.name'), v: (p) => p.name.toLowerCase(), r: (p) => h('span', null, p.name, p.container ? h('span', { class: 'tag', title: tr('web.container') }, '⧉ ' + p.container) : '') });
const colUser = () => ({ t: tr('tui.k.user'), v: (p) => p.user, r: (p) => p.user, c: 'nowrap' });
const colRisk = () => ({ t: tr('web.col.risk'), v: (p) => riskNum(p.risk) * 1000 + p.score, r: (p) => riskBadge(p.risk), desc: true });
const colPath = () => ({ t: tr('tui.k.path'), v: (p) => p.exe || '', r: (p) => h('span', { title: p.exe }, p.exe ? p.exe + (p.exeDeleted ? ' ' + tr('tui.deleted') : '') : (p.kernel ? tr('web.kernel_short') : '—')), c: 'path' });
const colCmd = () => ({ t: tr('web.col.cmdline'), v: (p) => p.cmdline, r: (p) => h('span', { title: p.cmdline, class: 'mono' }, p.cmdline || '—'), c: 'cmd' });

function renderSuspicious() {
  const f = procFilter();
  const rows = state.processes.filter((p) => p.risk !== 'INFO' && f(p));
  if (!state.sort['t-suspicious']) state.sort['t-suspicious'] = { col: 0, dir: -1 };
  renderTable('t-suspicious', [
    colRisk(), colPID(), colName(), colUser(),
    { t: tr('web.col.path_cmd'), v: (p) => p.exe, r: (p) => h('div', null, h('div', { class: 'mono', title: p.exe }, p.exe || '—'), h('div', { class: 'mono muted', title: p.cmdline }, p.cmdline.length > 140 ? p.cmdline.slice(0, 140) + '…' : p.cmdline)), c: 'wrap' },
    { t: tr('tui.h.findings'), v: (p) => p.findings.length, r: findingTags, c: 'wrap', desc: true },
    { t: tr('web.col.score'), v: (p) => p.score, r: (p) => p.score, c: 'num', desc: true },
    { t: tr('tui.k.first'), v: (p) => p.firstSeen, r: (p) => fmtTime(p.firstSeen), c: 'nowrap' },
    { t: tr('tui.k.last'), v: (p) => p.lastSeen, r: (p) => fmtTime(p.lastSeen), c: 'nowrap' },
    { t: tr('tui.h.recommendation'), v: () => 0, r: (p) => tx(p.recommendations && p.recommendations[0]), c: 'wrap' },
  ], rows, (p) => openCard(p.key), tr('web.empty.suspicious'));
}

function renderAllProcs() {
  const rows = state.processes.filter(procFilter());
  renderTable('t-all', [
    colPID(),
    { t: 'PPID', v: (p) => p.ppid, r: (p) => p.ppid, c: 'num' },
    colName(), colUser(),
    { t: 'CPU %', v: (p) => p.cpuPercent, r: (p) => fmtPct(p.cpuPercent) + (p.cpuAverage ? '*' : ''), c: 'num', desc: true },
    { t: 'RAM', v: (p) => p.rssBytes, r: (p) => fmtBytes(p.rssBytes), c: 'num', desc: true },
    { t: tr('web.col.uptime'), v: (p) => p.startTime, r: (p) => fmtAgo(p.startTime), c: 'nowrap' },
    colPath(), colCmd(), colRisk(),
  ], rows, (p) => openCard(p.key));
}

function renderNet() {
  const q = $('n-q').value.trim().toLowerCase();
  const proto = $('n-proto').value;
  const st = $('n-state').value;
  const ext = $('n-external').checked;
  const isLocal = (a) => !a || a === '0.0.0.0' || a === '::' || a.startsWith('127.') || a === '::1';
  const rows = state.sockets.filter((s) => {
    if (proto && s.proto !== proto) return false;
    if (st && s.state !== st) return false;
    if (ext && isLocal(s.remoteAddr)) return false;
    if (q) {
      const hay = [s.localAddr, s.localPort, s.remoteAddr, s.remotePort, s.procName, s.pid, s.user].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  renderTable('t-net', [
    { t: tr('tui.k.proto'), v: (s) => s.proto, r: (s) => s.proto },
    { t: tr('tui.k.local'), v: (s) => s.localPort, r: (s) => `${s.localAddr}:${s.localPort}`, c: 'mono' },
    { t: tr('tui.k.remote'), v: (s) => s.remoteAddr, r: (s) => (s.remotePort ? `${s.remoteAddr}:${s.remotePort}` : '—'), c: 'mono' },
    { t: tr('tui.k.state'), v: (s) => s.state, r: (s) => s.state },
    { t: 'PID', v: (s) => s.pid || 0, r: (s) => s.pid || '—', c: 'num' },
    { t: tr('tui.title.process'), v: (s) => s.procName || '', r: (s) => s.procName || h('span', { class: 'muted', title: tr('tui.no_owner') }, tr('tui.unknown')) },
    { t: tr('tui.k.user'), v: (s) => s.user || '', r: (s) => s.user || '' },
    { t: 'Netns', v: (s) => s.netns || '', r: (s) => s.netns || '', c: 'mono' },
  ], rows, (s) => s.procKey && openCard(s.procKey));
}

function renderPorts() {
  const x = state.exposure;
  if (!x) return;
  const addrs = (x.addrs || []).filter((a) => a.scope !== 'loopback');
  $('ports-addrs').replaceChildren(...(addrs.length ? addrs.map((a) => h('li', { class: 'mono' }, a.addr + (a.iface ? ` (${a.iface})` : '') + ' — ' + label(SCOPE_NAMES, a.scope)))
    : [h('li', { class: 'muted' }, tr('web.ports.no_addrs'))]));
  const fw = x.firewall || {};
  $('ports-fw').replaceChildren(
    ...kv('ufw', label(UFW_NAMES, fw.ufw) + (fw.ufw === 'active' ? ' · ' + tr('tui.ufw.policy', fw.defaultInput, fw.rules) : '')),
    ...kv('Docker', (x.bindings || []).length ? tr('tui.ports.bindings', x.bindings.length) : tr('tui.ports.no_bindings')),
  );

  const q = $('p-q').value.trim().toLowerCase();
  const scope = $('p-scope').value;
  const risky = $('p-risky').checked;
  const rows = (x.entries || []).filter((e) => {
    if (scope && e.scope !== scope) return false;
    if (risky && (riskNum(e.risk) < 1 || e.suppressed)) return false;
    if (q) {
      const hay = [e.proto, e.addr, e.port, e.service && e.service.name, e.procName, e.pid, e.user, e.exe, e.container,
        e.docker && e.docker.image].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  if (!state.sort['t-ports']) state.sort['t-ports'] = { col: 0, dir: -1 };
  renderTable('t-ports', [
    { t: tr('web.col.risk'), v: (e) => riskNum(e.risk) * 10 + (e.scope === 'public' ? 1 : 0), r: (e) => h('span', null, riskBadge(e.risk), e.suppressed ? h('span', { class: 'tag' }, tr('tui.suppressed')) : ''), desc: true },
    { t: tr('tui.k.proto'), v: (e) => e.proto, r: (e) => e.proto },
    { t: tr('tui.k.address'), v: (e) => e.port, r: (e) => endpoint(e.addr, e.port), c: 'mono' },
    { t: tr('tui.k.reach'), v: (e) => e.scope, r: (e) => h('span', null, label(SCOPE_NAMES, e.scope),
      e.allInterfaces ? h('span', { class: 'tag', title: tr('tui.all_ifaces_title') }, tr('tui.all_ifaces')) : '',
      e.firewall ? h('span', { class: 'tag' + (e.firewall === 'bypassed' ? ' strong' : '') }, label(FW_NAMES, e.firewall)) : '') },
    { t: tr('tui.k.service'), v: (e) => (e.service ? e.service.name : ''), r: (e) => (e.service ? e.service.name : '—') },
    { t: tr('tui.title.process'), v: (e) => e.procName || '', r: (e) => (e.pid ? `${e.procName} (${e.pid}, ${e.user})` : h('span', { class: 'muted' }, e.docker ? 'docker' : tr('tui.unknown'))) },
    { t: tr('tui.k.container'), v: (e) => e.container || '', r: (e) => (e.docker ? `${e.container} (${e.docker.image || '?'}) → ${e.docker.containerPort}` : (e.container || '')), c: 'wrap' },
    { t: tr('tui.h.facts'), v: () => 0, r: (e) => h('ul', { class: 'findings' }, (e.evidence || []).slice(1).map((m) => h('li', null, tx(m)))), c: 'wrap' },
    { t: tr('tui.h.recommendation'), v: () => 0, r: (e) => tx(e.recommendation), c: 'wrap' },
  ], rows, (e) => e.procKey && openCard(e.procKey), tr('web.ports.empty'));
}

function renderHistory() {
  const q = $('h-q').value.trim().toLowerCase();
  const type = $('h-type').value;
  const risk = $('h-risk').value;
  const rows = state.events.filter((e) => {
    if (type && e.type !== type) return false;
    if (risk && riskNum(e.risk) < riskNum(risk)) return false;
    if (q && ![e.pid, e.name, e.user, e.exe, tx(e.details)].join(' ').toLowerCase().includes(q)) return false;
    return true;
  });
  renderTable('t-history', [
    { t: tr('web.col.time'), v: (e) => e.time, r: (e) => fmtTime(e.time), c: 'nowrap' },
    { t: tr('tui.title.event'), v: (e) => e.type, r: (e) => eventName(e.type), c: 'nowrap' },
    { t: 'PID', v: (e) => e.pid || 0, r: (e) => e.pid || '', c: 'num' },
    { t: tr('tui.k.name'), v: (e) => e.name || '', r: (e) => e.name || '' },
    { t: tr('tui.k.user'), v: (e) => e.user || '', r: (e) => e.user || '' },
    { t: tr('tui.title.details'), v: (e) => tx(e.details), r: (e) => tx(e.details), c: 'wrap' },
    { t: tr('web.col.risk'), v: (e) => riskNum(e.risk), r: (e) => riskBadge(e.risk), desc: true },
  ], rows, (e) => e.key && openCard(e.key), tr('web.empty.events'));
}

function renderSystem() {
  const s = state.system;
  if (!s) return;
  const host = s.host || {};
  $('sys-host').replaceChildren(
    ...kv(tr('tui.k.host'), host.hostname), ...kv(tr('web.k.os'), host.os || '—'), ...kv(tr('web.k.kernel'), host.kernel || '—'),
    ...kv(tr('tui.k.boot'), fmtTime(host.bootTime) + ' (' + tr('tui.ago', fmtAgo(host.bootTime)) + ')'), ...kv(tr('web.k.ram'), fmtBytes(host.memTotal)),
    ...kv(tr('tui.k.root'), yesNo(host.isRoot)), ...kv(tr('tui.k.in_container'), yesNo(host.inContainer)),
    ...kv(tr('web.k.version'), state.status ? state.status.version : ''),
  );
  const warns = s.warnings && s.warnings.length ? s.warnings.map(tx) : [tr('web.no_limits')];
  $('sys-warn').replaceChildren(...warns.map((w) => h('li', null, w)));
  renderTable('t-system', [
    { t: tr('web.col.risk'), v: (f) => riskNum(f.risk), r: (f) => riskBadge(f.risk), desc: true },
    { t: tr('tui.title.check'), v: (f) => tx(f.title), r: (f) => tx(f.title), c: 'wrap' },
    { t: tr('tui.k.file'), v: (f) => f.path, r: (f) => f.path, c: 'mono' },
    { t: tr('tui.k.modified'), v: (f) => f.modTime || '', r: (f) => fmtTime(f.modTime), c: 'nowrap' },
    { t: tr('tui.h.facts'), v: () => 0, r: (f) => h('ul', { class: 'findings' }, (f.evidence || []).map((e) => h('li', { class: 'mono' }, tx(e)))), c: 'wrap' },
    { t: tr('tui.h.recommendation'), v: () => 0, r: (f) => tx(f.recommendation), c: 'wrap' },
  ], s.findings || [], null, tr('web.empty.system'));
}

function yesNo(v) { return v ? tr('tui.yes') : tr('tui.no'); }

function kv(k, v) { return [h('dt', null, k), h('dd', null, v === undefined || v === null ? '—' : String(v))]; }

// ---------------------------------------------------------------------
// Дерево процессов
// ---------------------------------------------------------------------

function renderTree() {
  const box = $('tree');
  if (!state.tree) { box.replaceChildren(h('div', { class: 'empty' }, tr('web.loading'))); return; }
  const q = $('tree-q').value.trim().toLowerCase();
  const showKernel = $('tree-kernel').checked;
  const match = (n) => q && [n.pid, n.name, n.exe, n.cmdline].join(' ').toLowerCase().includes(q);
  // Есть ли совпадение в поддереве — такие ветки при поиске раскрываются.
  const hasMatch = (n) => match(n) || n.children.some(hasMatch);
  const build = (nodes) => {
    const ul = h('ul');
    for (const n of nodes) {
      if (!showKernel && n.kernel) continue;
      const kids = n.children.filter((c) => showKernel || !c.kernel);
      const collapsed = state.collapsed.has(n.key) && !(q && kids.some(hasMatch));
      const li = h('li', null,
        h('span', { class: 'toggle', onclick: () => { toggleNode(n.key); } }, kids.length ? (collapsed ? '▸' : '▾') : '·'),
        h('span', { class: 'node' + (match(n) ? ' hl' : ''), title: n.cmdline || n.exe, onclick: () => openCard(n.key) },
          riskBadge(n.risk), h('span', { class: 'pid' }, n.pid), h('b', null, n.name), h('span', { class: 'muted' }, n.user),
          h('span', { class: 'muted mono' }, n.exe || '')),
      );
      if (kids.length && !collapsed) li.append(build(kids));
      ul.append(li);
    }
    return ul;
  };
  box.replaceChildren(build(state.tree.roots));
}

function toggleNode(key) {
  if (state.collapsed.has(key)) state.collapsed.delete(key); else state.collapsed.add(key);
  renderTree();
}

function walkTree(fn) {
  const rec = (nodes) => nodes.forEach((n) => { fn(n); rec(n.children); });
  if (state.tree) rec(state.tree.roots);
}

// ---------------------------------------------------------------------
// Карточка процесса
// ---------------------------------------------------------------------

let cardData = null;

async function openCard(key) {
  try {
    const data = await api('/api/process/' + encodeURIComponent(key));
    cardData = data;
    history.replaceState(null, '', '#p=' + encodeURIComponent(key));
    renderCard(data);
    $('modal').classList.remove('hidden');
  } catch (e) {
    toast(tr('web.card_error', e.message));
  }
}

function closeCard() {
  $('modal').classList.add('hidden');
  cardData = null;
  history.replaceState(null, '', location.pathname);
}

function section(title, ...content) { return h('section', null, h('h3', null, title), ...content); }

function renderCard(data) {
  const body = $('m-body');
  if (data.exited) {
    const t = data.track;
    $('m-title').replaceChildren(tr('web.card.exited_title', t.pid, t.name));
    body.replaceChildren(
      h('dl', { class: 'kv' }, ...kv(tr('tui.k.user'), t.user), ...kv(tr('tui.k.path'), t.exe), ...kv(tr('tui.k.command'), t.cmdline),
        ...kv(tr('tui.k.first'), fmtTime(t.firstSeen)), ...kv(tr('tui.k.last'), fmtTime(t.lastSeen)), ...kv(tr('tui.k.last_risk'), t.risk)),
      eventsSection(data.events),
    );
    return;
  }
  const p = data.process;
  $('m-title').replaceChildren(riskBadge(p.risk), ` PID ${p.pid} · ${p.name}`);
  const active = p.findings.filter((f) => f.category !== 'info');
  const info = p.findings.filter((f) => f.category === 'info');

  const chain = h('div', { class: 'chain' });
  const anc = (data.ancestors || []).slice().reverse();
  anc.forEach((a) => chain.append(h('a', { onclick: () => openCard(a.key), title: a.exe }, `${a.name} (${a.pid})`), ' → '));
  chain.append(h('b', null, `${p.name} (${p.pid})`));

  body.replaceChildren(
    section(tr('tui.h.assessment'),
      h('div', { class: 'explain' }, tx(p.explanation)),
      active.length ? active.map(findingBlock) : h('p', { class: 'muted' }, tr('web.card.no_findings')),
      p.recommendations && p.recommendations.length ? h('div', null, h('h3', null, tr('tui.h.recommendations')),
        h('ul', null, p.recommendations.map((r) => h('li', null, tx(r))))) : ''),
    section(tr('web.col.cmdline'),
      h('div', { class: 'cmd-head' }, h('span', { class: 'muted' }, tr('web.card.masked')),
        h('button', { class: 'small secondary', type: 'button', onclick: () => copyText(p.cmdline) }, tr('tui.hint.copy'))),
      h('pre', null, p.cmdline || tr('tui.empty_paren')),
      p.args && p.args.length > 1 ? h('details', null, h('summary', null, tr('web.card.args', p.args.length)),
        h('ol', { start: 0 }, p.args.map((a) => h('li', { class: 'mono' }, a)))) : ''),
    section(tr('tui.h.main'), h('dl', { class: 'kv' },
      ...kv('PID / PPID', `${p.pid} / ${p.ppid}`), ...kv(tr('web.k.comm'), p.name), ...kv(tr('tui.k.state'), p.state),
      ...kv(tr('tui.k.user'), `${p.user} (UID ${p.uid}, EUID ${p.euid}, GID ${p.gid})`),
      ...kv(tr('tui.k.exe'), p.exe ? p.exe + (p.exeDeleted ? ' ' + tr('tui.deleted') : '') : (p.kernel ? tr('tui.kernel_thread') : tr('tui.unavailable'))),
      ...kv(tr('tui.k.file_mode'), p.exeInfo ? tr('web.card.file_mode', p.exeInfo.mode, p.exeInfo.uid, fmtBytes(p.exeInfo.size), fmtTime(p.exeInfo.modTime)) : '—'),
      ...kv(tr('tui.k.cwd'), p.cwd || '—'),
      ...kv(tr('tui.k.started'), fmtTime(p.startTime) + ' (' + fmtAgo(p.startTime) + ')'),
      ...kv(tr('tui.k.first_seen'), fmtTime(p.firstSeen)), ...kv(tr('web.k.last_seen'), fmtTime(p.lastSeen)),
      ...kv('CPU', fmtPct(p.cpuPercent) + '%' + (p.cpuAverage ? ' ' + tr('tui.cpu_average') : '')),
      ...kv(tr('tui.k.memory'), tr('web.card.memory', fmtBytes(p.rssBytes), fmtPct(p.memPercent), fmtBytes(p.vmsBytes))),
      ...kv(tr('web.k.threads'), p.threads), ...kv(tr('web.k.fds'), p.fdCount),
      ...kv(tr('web.k.danger_env'), p.envFlags && p.envFlags.length ? p.envFlags.join(', ') + ' ' + tr('tui.env_values') : tr('tui.no')),
    )),
    section(tr('tui.h.chain'), chain,
      data.children && data.children.length ? h('p', null, tr('web.card.children'), data.children.map((c, i) => [i ? ', ' : '', h('a', { class: 'plink', onclick: () => openCard(c.key) }, `${c.name} (${c.pid})`)])) : h('p', { class: 'muted' }, tr('web.card.no_children'))),
    section(tr('web.card.container_ns'), h('dl', { class: 'kv' },
      ...kv(tr('tui.k.container'), p.containerRuntime ? `${p.containerRuntime} ${p.container || ''}` : tr('tui.no')),
      ...kv(tr('web.k.nspid'), p.nspid ? p.nspid.join(' → ') : '—'),
      ...kv(tr('web.k.foreign_ns'), p.foreignNs && p.foreignNs.length ? p.foreignNs.join(', ') : tr('tui.no')),
      ...Object.entries(p.namespaces || {}).flatMap(([k, v]) => kv('ns/' + k, v)),
    )),
    section(tr('web.card.connections'), socketsTable(p.sockets || [])),
    section(tr('tui.h.files', (p.files || []).length, p.fdCount), filesTable(p.files || [])),
    info.length ? section(tr('tui.h.info'), info.map(findingBlock)) : '',
    p.access && p.access.length ? section(tr('web.card.access'), h('p', null, tr('web.card.access_text', p.access.join(', ')))) : '',
    eventsSection(data.events),
  );
}

function findingBlock(f) {
  return h('div', { class: 'finding' + (f.strong ? ' strong' : '') + (f.suppressed ? ' supp' : '') },
    h('div', null, h('b', null, tx(f.title)), ' ',
      h('span', { class: 'tag' }, categoryName(f.category)),
      f.category !== 'info' ? h('span', { class: 'tag' }, tr('web.card.points', f.weight)) : '',
      f.strong ? h('span', { class: 'tag strong' }, tr('web.card.strong')) : '',
      f.suppressed ? h('span', { class: 'tag' }, tr('tui.suppressed')) : ''),
    h('ul', { class: 'ev' }, (f.evidence || []).map((e) => h('li', { class: 'mono' }, tx(e)))),
    tx(f.recommendation) ? h('div', { class: 'rec' }, '→ ' + tx(f.recommendation)) : '');
}

function socketsTable(socks) {
  const inet = socks.filter((s) => s.proto !== 'unix');
  const unix = socks.filter((s) => s.proto === 'unix');
  if (!socks.length) return h('p', { class: 'muted' }, tr('web.card.no_sockets'));
  return h('div', null,
    inet.length ? h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, [tr('tui.k.proto'), tr('tui.k.local'), tr('tui.k.remote'), tr('tui.k.state'), 'inode'].map((c) => h('th', null, c)))),
      h('tbody', null, inet.map((s) => h('tr', null, h('td', null, s.proto), h('td', { class: 'mono' }, `${s.localAddr}:${s.localPort}`),
        h('td', { class: 'mono' }, s.remotePort ? `${s.remoteAddr}:${s.remotePort}` : '—'), h('td', null, s.state), h('td', { class: 'num' }, s.inode)))))) : '',
    unix.length ? h('p', { class: 'muted' }, tr('web.card.unix', unix.length) + (unix.some((s) => s.path) ? ' (' + [...new Set(unix.map((s) => s.path).filter(Boolean))].slice(0, 5).join(', ') + ')' : '')) : '');
}

function filesTable(files) {
  if (!files.length) return h('p', { class: 'muted' }, tr('web.no_data'));
  return h('details', null, h('summary', null, tr('web.show')),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'fd'), h('th', null, tr('web.col.type')), h('th', null, tr('web.col.target')))),
      h('tbody', null, files.map((f) => h('tr', null, h('td', { class: 'num' }, f.fd), h('td', null, f.kind), h('td', { class: 'mono' }, f.target)))))));
}

function eventsSection(events) {
  if (!events || !events.length) return section(tr('tui.h.history'), h('p', { class: 'muted' }, tr('web.card.no_events')));
  return section(tr('tui.h.history'), h('ul', null, events.slice().reverse().map((e) =>
    h('li', null, fmtTime(e.time), ' — ', h('b', null, eventName(e.type)), ': ', tx(e.details)))));
}

// ---------------------------------------------------------------------
// Сводка, загрузка данных, обновление
// ---------------------------------------------------------------------

function renderSummary() {
  const s = state.status;
  if (!s || !s.ready) return;
  const host = s.host;
  $('hostline').textContent = tr('web.hostline', host.hostname, host.os || 'Linux', host.kernel || '?') + (s.demo ? ' · ' + tr('web.demo') : '');
  $('scaninfo').textContent = tr('web.scaninfo', fmtTime(s.time), s.durationMs, s.interval);
  const by = s.stats.byRisk;
  const badge = (n, r) => { const b = riskBadge(r); b.textContent = n; return b; };
  $('summary').replaceChildren(
    h('div', { class: 'stat', onclick: () => { $('f-risk').value = ''; switchTab('all'); renderAll(); } }, h('div', { class: 'num' }, s.stats.total), h('div', { class: 'lbl' }, tr('web.stat.processes'))),
    ...['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((r) => h('div', { class: 'stat', onclick: () => { $('f-risk').value = r; switchTab('suspicious'); renderAll(); } },
      h('div', { class: 'num' }, badge(by[r] || 0, r)), h('div', { class: 'lbl' }, r))),
    h('div', { class: 'stat', onclick: () => switchTab('net') }, h('div', { class: 'num' }, s.stats.sockets), h('div', { class: 'lbl' }, tr('web.stat.sockets'))),
    h('div', { class: 'stat', onclick: () => switchTab('ports') }, h('div', { class: 'num' }, s.stats.publicPorts || 0,
      s.stats.dangerousPorts ? h('span', { class: 'risk risk-HIGH', title: tr('web.stat.dangerous_title') }, ' ⚠ ' + s.stats.dangerousPorts) : ''), h('div', { class: 'lbl' }, tr('web.stat.public_ports'))),
    h('div', { class: 'stat', onclick: () => switchTab('system') }, h('div', { class: 'num' }, s.systemFindings || 0), h('div', { class: 'lbl' }, tr('web.stat.system'))),
  );
  const banner = $('banner');
  if (s.warnings && s.warnings.length) {
    banner.replaceChildren(h('b', null, tr('web.limits') + ' '), s.warnings.map(tx).join(' '));
    banner.classList.remove('hidden');
  } else banner.classList.add('hidden');
  $('btn-logout').classList.toggle('hidden', !s.auth);
  $('cnt-all').textContent = s.stats.total;
  $('cnt-suspicious').textContent = s.stats.total - (by.INFO || 0);
  $('cnt-net').textContent = s.stats.sockets;
  $('cnt-ports').textContent = s.stats.publicPorts || 0;
  $('cnt-system').textContent = s.systemFindings || 0;
}

function renderAll() {
  renderSummary();
  switch (state.tab) {
    case 'suspicious': renderSuspicious(); break;
    case 'all': renderAllProcs(); break;
    case 'tree': renderTree(); break;
    case 'net': renderNet(); break;
    case 'ports': renderPorts(); break;
    case 'history': renderHistory(); break;
    case 'system': renderSystem(); break;
  }
}

async function loadTabData() {
  switch (state.tab) {
    case 'tree': state.tree = await api('/api/tree'); break;
    case 'net': state.sockets = (await api('/api/connections')).sockets || []; break;
    case 'ports': state.exposure = (await api('/api/exposure')).exposure || null; break;
    case 'history': state.events = (await api('/api/events?limit=2000')).events || []; break;
    case 'system': state.system = await api('/api/system'); break;
  }
}

let loading = false;
async function refresh() {
  if (loading) return;
  loading = true;
  try {
    state.status = await api('/api/status');
    state.csrf = state.status.csrf;
    if (!state.status.ready) {
      $('hostline').textContent = tr('web.first_scan');
      setTimeout(refresh, 1500);
      return;
    }
    if (state.tab === 'suspicious' || state.tab === 'all') {
      state.processes = (await api('/api/processes')).processes || [];
    }
    await loadTabData();
    renderAll();
  } catch (e) {
    if (e.message !== 'unauthorized') toast(tr('web.refresh_error', e.message));
  } finally {
    loading = false;
  }
}

function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab').forEach((s) => s.classList.toggle('active', s.id === 'tab-' + tab));
  $('proc-filters').classList.toggle('hidden', !(tab === 'suspicious' || tab === 'all'));
  try { localStorage.setItem('ssg.tab', tab); } catch (_) { /* приватный режим */ }
  refresh();
}

let timer = null;
function setRefresh(sec) {
  clearInterval(timer);
  if (sec > 0) timer = setInterval(() => { if ($('modal').classList.contains('hidden')) refresh(); }, sec * 1000);
  try { localStorage.setItem('ssg.refresh', String(sec)); } catch (_) { /* приватный режим */ }
}

// ---------------------------------------------------------------------
// Инициализация
// ---------------------------------------------------------------------

async function init() {
  // Каталог переводов нужен до первой отрисовки; без него остаются ключи,
  // поэтому при ошибке повторяем загрузку при следующем обновлении.
  try { await loadLang(detectLang()); } catch (_) { /* сервер недоступен — покажет refresh */ }
  $('btn-lang').addEventListener('click', async () => {
    try {
      await switchLang();
      renderAll();
      if (cardData && !$('modal').classList.contains('hidden')) renderCard(cardData);
    } catch (e) { toast(e.message); }
  });

  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  for (const id of ['proc-filters', 'net-filters', 'ports-filters', 'hist-filters']) {
    const form = $(id);
    form.addEventListener('input', () => { state.showAll = {}; renderAll(); });
    form.addEventListener('submit', (e) => e.preventDefault());
    form.addEventListener('reset', () => setTimeout(renderAll, 0));
  }
  $('tree-q').addEventListener('input', renderTree);
  $('tree-kernel').addEventListener('change', renderTree);
  $('tree-expand').addEventListener('click', () => { state.collapsed.clear(); renderTree(); });
  $('tree-collapse').addEventListener('click', () => { walkTree((n) => { if (n.children.length) state.collapsed.add(n.key); }); renderTree(); });

  $('btn-rescan').addEventListener('click', async () => {
    try {
      await api('/api/rescan', { method: 'POST' });
      toast(tr('tui.flash.scan_started'));
      setTimeout(refresh, 1500);
    } catch (e) { toast(e.message); }
  });
  $('btn-logout').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' }).catch(() => {});
    location.href = '/login';
  });
  $('m-close').addEventListener('click', closeCard);
  $('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeCard(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('modal').classList.contains('hidden')) closeCard(); });
  $('m-copy-json').addEventListener('click', () => { if (cardData) copyText(JSON.stringify(cardData.process || cardData, null, 2)); });

  let sec = 10;
  try { sec = Number(localStorage.getItem('ssg.refresh') ?? 10); } catch (_) { /* приватный режим */ }
  $('refresh').value = String(sec);
  $('refresh').addEventListener('change', (e) => setRefresh(Number(e.target.value)));
  setRefresh(sec);

  // Вкладку можно задать ссылкой: #tab=net
  let tab = 'suspicious';
  try { tab = localStorage.getItem('ssg.tab') || tab; } catch (_) { /* приватный режим */ }
  const th = location.hash.match(/^#tab=(\w+)$/);
  if (th && document.querySelector(`.tabs button[data-tab="${th[1]}"]`)) tab = th[1];
  switchTab(tab);

  // Прямая ссылка на карточку: #p=<key>
  const m = location.hash.match(/^#p=(.+)$/);
  if (m) setTimeout(() => openCard(decodeURIComponent(m[1])), 300);
}

init();
