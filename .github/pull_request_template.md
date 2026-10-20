<!--
Thank you for your contribution! Please fill in the sections below.
Спасибо за ваш вклад! Пожалуйста, заполните разделы ниже.
Guidelines / Правила: CONTRIBUTING.md
-->

## What and why / Что и зачем

<!-- What does this pull request change, and why? / Что меняет этот pull request и зачем? -->

Closes #

## How it was tested / Как проверено

<!-- Commands, environment (distribution, kernel, container or not). / Команды, окружение (дистрибутив, ядро, контейнер или нет). -->

## Checklist / Проверка

- [ ] `make vet` and `make test` pass / `make vet` и `make test` проходят
- [ ] `shellcheck -x scripts/*.sh` passes (if scripts changed) / проходит (если менялись скрипты)
- [ ] New or changed rules are covered by tests, including a legitimate case / новые или изменённые правила покрыты тестами, включая легитимный случай
- [ ] New settings are added to `.env.example` with a comment / новые настройки добавлены в `.env.example` с комментарием
- [ ] Documentation updated in both `README.md` and `README.ru.md` (if needed) / документация обновлена в обоих README (если нужно)
- [ ] No external dependencies added; the application stays read-only / внешние зависимости не добавлены, приложение по-прежнему только читает
