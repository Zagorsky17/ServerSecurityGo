// Страница входа: отправляет пароль на /api/login и при успехе
// переходит в панель. Пароль нигде не сохраняется.
'use strict';

document.getElementById('login').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = document.getElementById('err');
  const input = document.getElementById('password');
  err.classList.add('hidden');
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-SSG-Lang': I18N.lang },
      body: JSON.stringify({ password: input.value }),
      credentials: 'same-origin',
    });
    if (r.ok) {
      location.href = '/';
      return;
    }
    const data = await r.json().catch(() => ({}));
    err.textContent = data.error || tr('web.err.status', r.status);
  } catch (e) {
    err.textContent = tr('web.err.unavailable');
  }
  input.value = '';
  err.classList.remove('hidden');
});

document.getElementById('btn-lang').addEventListener('click', () => {
  switchLang().catch(() => {});
});

// Без каталога остаётся русская разметка страницы — вход всё равно работает.
loadLang(detectLang()).catch(() => {});
