# Security Policy / Политика безопасности

[English](#english) | [Русский](#русский)

---

## English

### Supported versions

Security fixes are released for the latest release only. Please update with `/opt/serversecuritygo/scripts/update.sh` before reporting, if possible.

| Version | Supported |
|---|---|
| latest release | ✅ |
| older releases | ❌ |

### Reporting a vulnerability

If you believe you have found a vulnerability in ServerSecurityGo itself, please report it **privately** instead of opening a public issue. Examples include an authentication or CSRF bypass in the dashboard, secrets leaking into the UI, logs or history, privilege escalation through the service or scripts, or a way to make the scanner execute code.

1. Open the [Security tab](https://github.com/Zagorsky17/ServerSecurityGo/security) of the repository.
2. Click **"Report a vulnerability"** and fill in the form. Only the maintainers will see it.

Please include, if you can:

- the affected version and configuration (without secrets);
- steps to reproduce or a proof of concept;
- the impact as you understand it.

We will do our best to acknowledge your report within 7 days, keep you informed of progress, and credit you in the release notes if you wish. Please give us reasonable time to release a fix before disclosing the issue publicly.

### What is not a vulnerability

- **A missed detection or a false positive** is a detection-quality issue, not a vulnerability. Please report it through the regular ["False positive / missed detection" issue template](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose). The [detection limitations](README.md#detection-limitations) are documented: for example, kernel-level rootkits can hide from `/proc`.
- Problems that require an attacker to already have root on the monitored server.

### Responsible use

ServerSecurityGo is a monitoring tool for servers you own or are authorized to administer. Please do not use it, or information from reports, against systems you have no permission to test.

Thank you for helping keep ServerSecurityGo and its users safe!

---

## Русский

### Поддерживаемые версии

Исправления безопасности выпускаются только для последнего релиза. Пожалуйста, по возможности обновитесь командой `/opt/serversecuritygo/scripts/update.sh`, прежде чем сообщать о проблеме.

| Версия | Поддерживается |
|---|---|
| последний релиз | ✅ |
| более ранние релизы | ❌ |

### Как сообщить об уязвимости

Если вы считаете, что нашли уязвимость в самом ServerSecurityGo, пожалуйста, сообщите о ней **закрыто**, а не в публичном issue. Примеры: обход авторизации или CSRF в панели, утечка секретов в интерфейс, журнал или историю, повышение привилегий через службу или скрипты, способ заставить сканер выполнить код.

1. Откройте вкладку [Security](https://github.com/Zagorsky17/ServerSecurityGo/security) репозитория.
2. Нажмите **«Report a vulnerability»** и заполните форму. Её увидят только сопровождающие.

Пожалуйста, по возможности укажите:

- версию и конфигурацию (без секретов);
- шаги воспроизведения или proof of concept;
- последствия, как вы их понимаете.

Мы постараемся подтвердить получение в течение 7 дней, будем держать вас в курсе и, если хотите, упомянем вас в описании релиза. Пожалуйста, дайте нам разумное время на выпуск исправления, прежде чем раскрывать проблему публично.

### Что не считается уязвимостью

- **Пропуск обнаружения или ложное срабатывание** — это вопрос качества обнаружения, а не уязвимость. Пожалуйста, сообщайте о них через обычный [шаблон issue «Ложное срабатывание или пропуск»](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose). [Ограничения обнаружения](README.ru.md#ограничения-обнаружения) описаны в документации: например, руткиты уровня ядра могут скрываться от `/proc`.
- Проблемы, для которых злоумышленнику уже нужны права root на наблюдаемом сервере.

### Ответственное использование

ServerSecurityGo — инструмент мониторинга для серверов, которыми вы владеете или которые вправе администрировать. Пожалуйста, не используйте его и сведения из отчётов против систем, проверять которые у вас нет разрешения.

Спасибо, что помогаете сделать ServerSecurityGo и его пользователей безопаснее!
