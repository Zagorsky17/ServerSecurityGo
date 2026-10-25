// Перевод веб-панели и страницы входа (общий для app.js и login.js).
//
// Каталог переводов отдаёт сервер (/i18n/<язык>.json) — тот же, что
// использует терминальный интерфейс. Тексты с сервера (признаки,
// объяснения, события) приходят сообщениями {key, args} и собираются
// здесь функцией tx на выбранном языке.
//
// Безопасность: аргументы сообщений (имена процессов, командные строки)
// контролирует злоумышленник. Подстановка однопроходная — «{0}» внутри
// аргумента не раскрывается, — а результат выводится только через
// textContent / setAttribute.
'use strict';

const LANGS = ['ru', 'en'];
const I18N = { lang: 'ru', dict: {} };

/** Язык: выбор пользователя из localStorage, иначе язык страницы от сервера. */
function detectLang() {
  try {
    const saved = localStorage.getItem('ssg.lang');
    if (LANGS.includes(saved)) return saved;
  } catch (_) { /* приватный режим */ }
  const page = document.documentElement.lang;
  return LANGS.includes(page) ? page : 'ru';
}

/** Подставляет {N} за один проход: заменённый текст повторно не разбирается. */
function fmtTemplate(tmpl, args) {
  return tmpl.replace(/\{(\d{1,3})\}/g, (m, i) => (Number(i) < args.length ? args[Number(i)] : m));
}

/** Строка каталога по ключу. Неизвестный ключ выводится как есть. */
function tr(key, ...args) {
  const tmpl = I18N.dict[key];
  if (tmpl === undefined) return key;
  return fmtTemplate(tmpl, args.map((a) => String(a)));
}

/** Текст серверного сообщения: строка, {key, args} или {sep, parts}. */
function tx(m) {
  if (m === undefined || m === null) return '';
  if (typeof m === 'string') return m;
  if (Array.isArray(m.parts)) return m.parts.map(tx).filter((s) => s !== '').join(m.sep || '');
  if (typeof m.key === 'string') {
    const tmpl = I18N.dict[m.key];
    if (tmpl === undefined) return m.key;
    return fmtTemplate(tmpl, (m.args || []).map(tx));
  }
  return '';
}

/** Переводит статическую разметку: data-i18n, data-i18n-title, data-i18n-placeholder, data-i18n-aria-label. */
function applyStatic(root = document) {
  root.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = tr(el.dataset.i18n); });
  for (const attr of ['title', 'placeholder', 'aria-label']) {
    const data = 'i18n' + attr.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase());
    root.querySelectorAll(`[data-i18n-${attr}]`).forEach((el) => el.setAttribute(attr, tr(el.dataset[data])));
  }
}

/** Загружает каталог языка и переводит статическую разметку. */
async function loadLang(lang) {
  const r = await fetch('/i18n/' + lang + '.json', { credentials: 'same-origin' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  I18N.dict = await r.json();
  I18N.lang = lang;
  document.documentElement.lang = lang;
  applyStatic();
}

/** Запоминает выбор пользователя и загружает другой язык. */
async function switchLang() {
  const next = LANGS[(LANGS.indexOf(I18N.lang) + 1) % LANGS.length];
  try { localStorage.setItem('ssg.lang', next); } catch (_) { /* приватный режим */ }
  await loadLang(next);
}

/** Локаль для дат и чисел. */
function dateLocale() { return I18N.lang === 'en' ? 'en-GB' : 'ru-RU'; }
