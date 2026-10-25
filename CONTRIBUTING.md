# Contributing / Участие в разработке

[English](#english) | [Русский](#русский)

---

## English

Thank you for taking the time to contribute to ServerSecurityGo! Every bug report, false-positive report, idea and pull request helps make Linux servers a little safer. This guide explains how to take part. If anything is unclear, please feel free to ask in an issue — there are no silly questions.

By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md#english).

### Reporting a security vulnerability

**Please do not open a public issue for vulnerabilities** in ServerSecurityGo itself (for example, an authentication bypass in the dashboard or a way to leak secrets). Please follow [SECURITY.md](SECURITY.md#english) instead. We appreciate responsible disclosure.

### Opening an issue

Before opening an issue, please search the [existing issues](https://github.com/Zagorsky17/ServerSecurityGo/issues) — your topic may already be under discussion. Then [choose a template](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose):

- **Bug report** — something does not work as documented. Please include the version (`serversecuritygo version`), the OS and kernel (`uname -r`, `/etc/os-release`), steps to reproduce, and what you expected versus what happened.
- **False positive / missed detection** — a legitimate process got a high risk level, or a suspicious one was not flagged. Please attach the process card JSON ("Копировать JSON" button) or the output of `scan --format json`. **Before posting, please review it and remove anything you consider private** (host names, IP addresses, paths, user names). Secrets in command lines are masked automatically, but please check anyway.
- **Feature request** — a new detection rule, data source, dashboard improvement and so on. Please describe the problem you want to solve, not only the proposed solution.

You are welcome to write issues in English or Russian.

### Proposing changes with a pull request

1. For anything larger than a small fix, please open an issue first so we can agree on the approach before you invest your time.
2. Fork the repository and create a branch from `main` with a descriptive name: `fix/container-detection`, `feat/rule-ssh-tunnel`, `docs/install-debian`.
3. Make your changes (see the guidelines below).
4. Make sure all checks pass locally:
   ```bash
   make vet     # gofmt + go vet
   make test    # go test -race ./...
   shellcheck -x scripts/*.sh   # if you changed scripts
   ```
5. Push the branch and open a pull request against `main`. Please fill in the template: what changed, why, how it was tested, and the linked issue (`Closes #123`).
6. CI must be green. A maintainer will review your pull request; please do not be discouraged by questions or change requests — they are a normal part of the process. Once approved, the pull request is merged into `main`.

Small, focused pull requests are reviewed much faster than large ones. One logical change per pull request, please.

### Development guidelines

- **Standard library only.** The project deliberately has no external Go modules. Please discuss it in an issue before adding a dependency.
- **Read-only by design.** The application must never kill processes, delete files or change network rules. Pull requests that add such actions will not be accepted.
- **Evidence, not verdicts.** A detection rule returns facts (what was read and where) and is worded as an indicator that needs checking, never as "malware". If a legitimate case is known, lower the weight for that case rather than disabling the rule.
- **New detection rule:** add it to `internal/detect/rules.go` and to the `Rules` list, cover it with tests in `detect_test.go` (both a detection case and a legitimate case that must stay `INFO`), add its title and recommendation (`rule.<id>.title`, `rule.<id>.rec`) in both languages to `internal/i18n/catalog_detect.go`, and add its ID to the rule list in both READMEs.
- **New setting:** add it to `internal/config`, and add it to `.env.example` with a clear comment on a separate line: what it does, the default, whether it is required, and any pitfalls.
- **Tests on a fake `/proc`.** Use `internal/fakeproc` and `fakeproc.NewFS` so tests pass on any OS. Code that depends on the real `/proc` belongs in `*_linux_test.go`.
- **Web UI safety.** Process names and command lines are attacker-controlled. In `internal/web/static/app.js`, output text only via `textContent` (the `h()` helper) and never via `innerHTML`. Do not add inline scripts or styles (CSP).
- **Language.** Code comments are written in Russian and identifiers in English. Please follow the style of the surrounding code. If writing Russian is difficult for you, English comments are fine — we will help with translation during review.
- **User-visible texts** (UI, indicators, events, CLI output, log, errors) never go into the code as plain strings: add a key to the catalog in `internal/i18n/catalog_*.go` with both the Russian and the English text and use `i18n.T(key, args...)` (`tr('key')` in the web dashboard). Placeholders are `{0}`, `{1}`; facts from the system (paths, command lines) are passed as arguments. Tests fail if a key is missing, unused or has different placeholders in the two languages.
- **Commit messages** are written in English and briefly describe what changed and why.

### Testing on a real server

If your change affects data collection, the systemd unit or the scripts, please mention in the pull request where you tested it (distribution, kernel version, container or not). Changes to `deploy/serversecuritygo.service` can silently cut off access to other processes' data; after installing, please check that `stats.restricted` in `GET /api/status` is `0`.

Thank you again for helping improve ServerSecurityGo!

---

## Русский

Спасибо, что нашли время помочь ServerSecurityGo! Каждое сообщение об ошибке или ложном срабатывании, каждая идея и каждый pull request делают Linux-серверы немного безопаснее. Ниже описано, как принять участие. Если что-то непонятно, пожалуйста, не стесняйтесь спросить в issue: глупых вопросов не бывает.

Участвуя в проекте, вы соглашаетесь соблюдать наш [кодекс поведения](CODE_OF_CONDUCT.md#русский).

### Как сообщить об уязвимости

**Пожалуйста, не открывайте публичный issue об уязвимостях** в самом ServerSecurityGo, например об обходе авторизации панели или утечке секретов. Вместо этого воспользуйтесь порядком из [SECURITY.md](SECURITY.md#русский). Мы ценим ответственное раскрытие.

### Как открыть issue

Перед созданием issue, пожалуйста, поищите среди [существующих](https://github.com/Zagorsky17/ServerSecurityGo/issues): возможно, ваш вопрос уже обсуждается. Затем [выберите шаблон](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose):

- **Сообщение об ошибке** — что-то работает не так, как описано в документации. Пожалуйста, укажите версию (`serversecuritygo version`), ОС и ядро (`uname -r`, `/etc/os-release`), шаги воспроизведения, ожидаемый и фактический результат.
- **Ложное срабатывание или пропуск** — легитимный процесс получил высокий риск или подозрительный процесс не был отмечен. Пожалуйста, приложите JSON карточки процесса (кнопка «Копировать JSON») или вывод `scan --format json`. **Перед публикацией просмотрите данные и удалите всё, что считаете конфиденциальным:** имена хостов, IP-адреса, пути, имена пользователей. Секреты в командных строках маскируются автоматически, но, пожалуйста, всё равно проверьте.
- **Предложение** — новое правило обнаружения, источник данных, улучшение панели и т. п. Пожалуйста, опишите задачу, которую хотите решить, а не только предлагаемое решение.

Issue можно писать на русском или английском языке.

### Как предложить изменения через pull request

1. Если изменение больше мелкого исправления, пожалуйста, сначала откройте issue. Так мы договоримся о подходе до того, как вы потратите время.
2. Сделайте форк репозитория и создайте ветку от `main` с понятным именем: `fix/container-detection`, `feat/rule-ssh-tunnel`, `docs/install-debian`.
3. Внесите изменения (см. рекомендации ниже).
4. Убедитесь, что локально проходят все проверки:
   ```bash
   make vet     # gofmt + go vet
   make test    # go test -race ./...
   shellcheck -x scripts/*.sh   # если меняли скрипты
   ```
5. Отправьте ветку и откройте pull request в `main`. Пожалуйста, заполните шаблон: что изменено, зачем, как проверено, и ссылку на issue (`Closes #123`).
6. CI должен быть зелёным. Сопровождающий проверит pull request. Пожалуйста, не расстраивайтесь из-за вопросов и просьб что-то поправить: это обычная часть работы. После одобрения pull request вливается в `main`.

Небольшие и сфокусированные pull request'ы проверяются гораздо быстрее больших. Пожалуйста, одно логическое изменение в одном pull request.

### Рекомендации по разработке

- **Только стандартная библиотека.** В проекте намеренно нет внешних модулей Go. Пожалуйста, обсудите в issue, прежде чем добавлять зависимость.
- **Только чтение.** Приложение никогда не завершает процессы, не удаляет файлы и не меняет сетевые правила. Pull request'ы, добавляющие такие действия, не принимаются.
- **Факты, а не вердикты.** Правило обнаружения возвращает факты (что прочитано и откуда) и формулируется как признак, требующий проверки, но никогда как «вредонос». Если известен легитимный случай, снижайте вес для этого случая, а не отключайте правило.
- **Новое правило обнаружения:** добавьте его в `internal/detect/rules.go` и в список `Rules`, покройте тестами в `detect_test.go` (и случай срабатывания, и легитимный случай, который должен остаться `INFO`), добавьте заголовок и рекомендацию (`rule.<id>.title`, `rule.<id>.rec`) на обоих языках в `internal/i18n/catalog_detect.go` и идентификатор в список правил в обоих README.
- **Новая настройка:** добавьте её в `internal/config` и в `.env.example` с понятным комментарием на отдельной строке: назначение, значение по умолчанию, обязательность, подводные камни.
- **Тесты на поддельном `/proc`.** Используйте `internal/fakeproc` и `fakeproc.NewFS`, чтобы тесты проходили на любой ОС. Код, зависящий от настоящего `/proc`, тестируйте в `*_linux_test.go`.
- **Безопасность интерфейса.** Имена процессов и командные строки контролирует злоумышленник. В `internal/web/static/app.js` выводите текст только через `textContent` (помощник `h()`), никогда через `innerHTML`. Не добавляйте inline-скрипты и стили (CSP).
- **Язык.** Комментарии в коде пишутся на русском, идентификаторы на английском. Пожалуйста, придерживайтесь стиля окружающего кода. Если писать по-русски вам трудно, английские комментарии тоже подойдут: мы поможем с переводом при проверке.
- **Тексты для пользователя** (интерфейс, признаки, события, вывод CLI, журнал, ошибки) не пишутся в коде строками: добавьте ключ в каталог `internal/i18n/catalog_*.go` сразу с русским и английским текстом и используйте `i18n.T(ключ, аргументы...)` (в веб-панели — `tr('ключ')`). Плейсхолдеры — `{0}`, `{1}`; факты из системы (пути, командные строки) передаются аргументами. Тесты падают, если ключа нет, он не используется или плейсхолдеры в языках различаются.
- **Сообщения коммитов** пишутся на английском и кратко описывают, что изменено и зачем.

### Проверка на реальном сервере

Если изменение затрагивает сбор данных, systemd-юнит или скрипты, пожалуйста, укажите в pull request, где вы его проверяли: дистрибутив, версия ядра, контейнер или нет. Изменения в `deploy/serversecuritygo.service` могут незаметно лишить сканер доступа к данным других процессов. После установки, пожалуйста, проверьте, что `stats.restricted` в `GET /api/status` равно `0`.

Ещё раз спасибо за помощь в развитии ServerSecurityGo!
