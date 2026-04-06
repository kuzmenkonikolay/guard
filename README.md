# FileGuard — защита чувствительных файлов на macOS

Система защиты SSH ключей, credentials, Keychain и браузерных данных от кражи малварью.

Все чувствительные файлы передаются во владение root — ни один процесс под твоим юзером (включая малварь) не может их прочитать. Доступ только через явное подтверждение в macOS диалоге.

---

## Часть 1: Установка (с нуля)

### Шаг 1. Скачать/скопировать папку guard

Скопируй папку `guard` в `~/work/guard/` (или куда удобно). В ней должны быть:

```
guard/
├── guard                    # главный скрипт
├── fileguard-daemon.sh      # демон мониторинга файлов
├── procguard-daemon.sh      # демон мониторинга процессов
├── config                   # какие файлы защищать
├── whitelist-procs          # разрешённые процессы
├── logs/                    # логи (создастся автоматически)
└── plists/
    ├── com.guard.fileguard.plist
    └── com.guard.procguard.plist
```

### Шаг 2. Сделать скрипты исполняемыми

Открой Терминал и выполни:

```bash
chmod +x ~/work/guard/guard
chmod +x ~/work/guard/fileguard-daemon.sh
chmod +x ~/work/guard/procguard-daemon.sh
```

### Шаг 3. Создать папку для логов

```bash
mkdir -p ~/work/guard/logs
```

### Шаг 4. Создать симлинк для команды `guard`

Это позволит запускать `guard` из любой директории:

```bash
sudo ln -sf ~/work/guard/guard /usr/local/bin/guard
```

Введи пароль когда попросит. Проверь что работает:

```bash
guard help
```

Должен показать список команд.

### Шаг 5. Заблокировать файлы

```bash
sudo guard init
```

Что произойдёт:
- Все SSH ключи (`~/.ssh/id_*`) станут принадлежать root
- Keychain (`~/Library/Keychains/login.keychain-db`) станет принадлежать root
- Если есть `.env`, `.aws/credentials`, `.kube/config` и т.д. — тоже будут заблокированы
- Будут сгенерированы SHA-256 хеши скриптов guard (integrity protection)

Проверь что сработало:

```bash
cat ~/.ssh/id_ed25519
```

Должен выдать: `Permission denied`

### Шаг 6. Запустить FileGuard демон (мониторинг файлов)

Этот демон работает от root и каждые 30 секунд проверяет что защищённые файлы не были изменены:

```bash
sudo cp ~/work/guard/plists/com.guard.fileguard.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.guard.fileguard.plist
```

### Шаг 7. Запустить ProcessGuard демон (мониторинг процессов)

Этот демон работает от твоего юзера и каждые 2 секунды сканирует новые процессы:

```bash
mkdir -p ~/Library/LaunchAgents
cp ~/work/guard/plists/com.guard.procguard.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.guard.procguard.plist
```

### Шаг 8. Проверить что всё работает

```bash
guard status
```

Должен показать:
```
  [ssh]        LOCKED
  [keychain]   LOCKED
  SIP:         enabled
  FileGuard:   running
  ProcessGuard: running
```

### Шаг 9 (рекомендуется). Установить LuLu

LuLu — бесплатный open-source firewall. Показывает диалог подтверждения для КАЖДОГО нового исходящего сетевого соединения.

1. Скачай с https://objective-see.org/products/lulu.html
2. Установи как обычное приложение
3. Разреши System Extension в Системных настройках когда попросит
4. При первом запуске выбери "Block" по умолчанию — потом будешь разрешать по одному

---

## Часть 2: Ежедневное использование

### Разблокировать SSH ключи (для git push, ssh и т.д.)

```bash
sudo guard unlock ssh
```

1. Появится macOS диалог: "Разблокировать ssh на 5 минут?"
2. Нажми "Allow 5 min"
3. SSH ключи доступны 5 минут
4. Через 5 минут автоматически заблокируются обратно
5. В углу экрана появится уведомление когда заблокируются

### Разблокировать .env файлы проекта

```bash
sudo guard unlock env ~/work/myproject
```

### Разблокировать всё сразу (не рекомендуется)

```bash
sudo guard unlock all
```

### Заблокировать обратно вручную (не дожидаясь таймаута)

```bash
sudo guard lock          # заблокировать всё
sudo guard lock ssh      # только SSH
```

### Посмотреть статус

```bash
guard status
```

### Посмотреть лог (кто и когда разблокировал)

```bash
guard log
```

### Добавить новый файл под защиту

Например, добавил `.env` в проект:

```bash
sudo guard add ~/work/myproject/.env env
```

### Убрать файл из защиты

```bash
sudo guard remove ~/work/myproject/.env
```

### Проверить целостность скриптов guard

```bash
guard verify
```

Если кто-то подменил скрипты guard — покажет ALARM с macOS диалогом.

---

## Часть 3: Что происходит автоматически

### FileGuard демон (фоновый)

- Каждые 30 секунд проверяет что защищённые файлы принадлежат root
- Если кто-то изменил permissions минуя guard — покажет ALARM и восстановит защиту
- Логирует в `~/work/guard/logs/access.log`

### ProcessGuard демон (фоновый)

- Каждые 2 секунды сканирует новые процессы
- Ловит подозрительные паттерны:
  - `node -e "..."` — именно так запускался Beavertail
  - `python -c "..."` — inline code execution
  - `curl ... | sh` — скачать и выполнить
  - Неизвестные процессы с сетевыми подключениями
- Показывает диалог с выбором: Kill / Allow Once / Add to Whitelist
- Логирует в `~/work/guard/logs/process.log`

### Integrity Check (при каждом запуске guard)

- При каждой команде guard проверяет SHA-256 хеши своих скриптов
- Если хеш не совпал — ALARM, guard отказывается работать
- Это защита от подмены самого guard малварью

---

## Часть 4: Типичные сценарии

### "Хочу сделать git push"

```bash
sudo guard unlock ssh
# делаешь git push
# через 5 минут само заблокируется
```

### "Хочу подключиться к серверу по SSH (туннель, сессия)"

```bash
sudo guard unlock ssh --session
ssh user@server
# ключи остаются разблокированы пока SSH-сессия активна
# как только закроешь SSH — автоматически заблокируется
```

Это работает и для SSH-туннелей, и для нескольких сессий одновременно — заблокирует когда закроются ВСЕ SSH-соединения.

### "Хочу работать долго и сам заблокирую когда закончу"

```bash
sudo guard unlock ssh --manual
# работаешь сколько нужно
# когда закончил:
sudo guard lock ssh
```

### "Хочу редактировать Rails credentials"

```bash
sudo guard unlock env
EDITOR=vim rails credentials:edit
# когда закончил — через 5 минут само заблокируется
```

Для production credentials:
```bash
sudo guard unlock env
EDITOR=vim rails credentials:edit --environment production
```

Guard защищает `config/master.key`, `config/credentials/*.key` во всех проектах в `~/work/`. После клонирования нового проекта с credentials запусти `sudo guard init` чтобы подхватить новые ключи.

### "Хочу запустить проект локально (нужен .env)"

```bash
sudo guard unlock env ~/work/myproject
# запускаешь yarn dev / npm start
# через 5 минут .env заблокируется — перезапуск потребует нового unlock
```

Для долгой разработки:
```bash
sudo guard unlock env ~/work/myproject --manual
# yarn dev
# когда закончил: sudo guard lock env
```

### "ProcessGuard показал алерт на процесс — что делать?"

- **Kill Process** — убить процесс. Используй если не знаешь что это.
- **Allow Once** — разрешить один раз. Процесс продолжит работать, но при следующем запуске снова спросит.
- **Add to Whitelist** — разрешить навсегда. Используй для своих инструментов.

### "Integrity ALARM — что делать?"

Это значит кто-то изменил скрипты guard. Если это был ты (обновление guard) — обнови хеши:

```bash
sudo guard update-integrity
```

Если ты НЕ менял скрипты — это может быть атака. Проверь:

```bash
# Посмотри что изменилось:
cat ~/work/guard/guard | head -5
# Сверь с оригиналом
```

---

## Часть 5: Управление демонами

### Остановить демоны

```bash
# FileGuard
sudo launchctl unload /Library/LaunchDaemons/com.guard.fileguard.plist

# ProcessGuard
launchctl unload ~/Library/LaunchAgents/com.guard.procguard.plist
```

### Перезапустить демоны

```bash
# FileGuard
sudo launchctl unload /Library/LaunchDaemons/com.guard.fileguard.plist
sudo launchctl load /Library/LaunchDaemons/com.guard.fileguard.plist

# ProcessGuard
launchctl unload ~/Library/LaunchAgents/com.guard.procguard.plist
launchctl load ~/Library/LaunchAgents/com.guard.procguard.plist
```

### Посмотреть логи демонов

```bash
# Ошибки FileGuard
cat ~/work/guard/logs/fileguard-stderr.log

# Ошибки ProcessGuard
cat ~/work/guard/logs/procguard-stderr.log
```

### Демоны запускаются автоматически при перезагрузке

Ничего делать не надо — LaunchDaemon и LaunchAgent стартуют при загрузке системы.

---

## Часть 6: Категории файлов

| Категория | Что защищает | Когда нужен unlock |
|-----------|-------------|-------------------|
| `ssh` | SSH ключи, config | git push/pull, ssh в серверы |
| `env` | .env файлы | запуск проектов локально |
| `aws` | AWS credentials | aws cli команды |
| `kube` | kubectl config | kubectl команды |
| `gpg` | GPG приватные ключи | подпись коммитов |
| `keychain` | macOS Keychain | редко нужен вручную |
| `browser` | Cookies, пароли, расширения | не трогать — браузер обращается сам |
| `wallets` | Крипто-кошельки | не трогать |
| `all` | Всё сразу | не рекомендуется |

---

## Часть 7: FAQ

**Q: Я перезагрузил Mac — файлы всё ещё заблокированы?**
A: Да. Файлы принадлежат root, это не сбрасывается при перезагрузке. Демоны тоже стартуют автоматически.

**Q: Забыл sudo перед guard unlock — что делать?**
A: guard сам попросит sudo если нужно.

**Q: SSH agent перестал работать после guard init**
A: Нужно `sudo guard unlock ssh` перед `ssh-add`.

**Q: Как обновить скрипты guard?**
A: Измени файлы, потом `sudo guard update-integrity` чтобы пересчитать хеши.

**Q: guard показывает "NO FILES" для категории**
A: Файлов этой категории нет на диске. Когда создашь (например `.env`) — добавь через `sudo guard add`.

**Q: ProcessGuard слишком часто алертит**
A: Добавь легитимные процессы в whitelist через диалог (кнопка "Add to Whitelist") или отредактируй `~/work/guard/whitelist-procs`.

---

## Часть 8: Secure Enclave SSH ключи (Apple Silicon)

Максимальная защита SSH ключей — приватный ключ хранится в аппаратном чипе Secure Enclave и **никогда** не покидает его. Даже root с полным доступом к файловой системе не может извлечь ключ. Операции подписи происходят внутри чипа.

Требования: Mac с Apple Silicon (M1/M2/M3/M4).

### Установка Secretive

Secretive — open-source SSH agent который хранит ключи в Secure Enclave.

```bash
brew install --cask secretive
```

### Настройка

1. Открой Secretive из Applications
2. Нажми "+" чтобы создать новый ключ
3. Выбери "Secure Enclave" (не "Store")
4. Дай имя ключу (например "GitHub SE")
5. Secretive покажет публичный ключ — скопируй его

### Добавить ключ в GitHub

1. Скопируй публичный ключ из Secretive
2. GitHub > Settings > SSH and GPG keys > New SSH key
3. Вставь ключ, дай имя, сохрани

### Настроить SSH agent

Secretive покажет инструкцию, но суть:

Добавь в `~/.ssh/config`:

```
Host *
    IdentityAgent /Users/nikolajkuzmenko/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

### Проверка

```bash
ssh -T git@github.com
```

При первом подключении Touch ID попросит подтверждение — это и есть аппаратная подпись через Secure Enclave.

### Как это защищает

| Угроза | Обычный SSH ключ | FileGuard SSH | Secure Enclave SSH |
|--------|-----------------|---------------|-------------------|
| Малварь под юзером | Может прочитать файл | Permission denied | Ключ не в файле |
| Малварь с root | Может прочитать файл | Может прочитать файл | Ключ не в файле |
| Физический доступ к диску | Может скопировать | Может скопировать | Ключ в чипе, не копируется |
| Подпись требует | Ничего | guard unlock | Touch ID |

Рекомендация: используй Secure Enclave SSH как основной ключ, а обычный SSH ключ под FileGuard как бэкап.
