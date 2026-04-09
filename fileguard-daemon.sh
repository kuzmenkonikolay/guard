#!/bin/bash
# FileGuard Daemon — мониторинг целостности защищаемых файлов
# Запускается как LaunchDaemon от root
# Каждые 30 секунд проверяет ownership/permissions

GUARD_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$GUARD_DIR/config"
LOG_FILE="$GUARD_DIR/logs/access.log"
CHECK_INTERVAL=30
CURRENT_USER="$(stat -f '%Su' /dev/console 2>/dev/null || echo 'nobody')"
HOME_DIR="$(eval echo ~"$CURRENT_USER")"

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [DAEMON] $1" >> "$LOG_FILE"
}

alert_user() {
    local message="$1"
    # Показать диалог от имени консольного пользователя
    local uid
    uid=$(id -u "$CURRENT_USER" 2>/dev/null || echo 501)
    launchctl asuser "$uid" osascript -e "display dialog \"$message\" buttons {\"OK\"} default button \"OK\" with icon stop with title \"FileGuard ALARM\"" 2>/dev/null || true
    # Также notification
    launchctl asuser "$uid" osascript -e "display notification \"$message\" with title \"FileGuard ALARM\"" 2>/dev/null || true
}

get_all_protected_files() {
    while IFS='|' read -r cat path; do
        [[ "$cat" =~ ^#.*$ || -z "$cat" ]] && continue
        cat=$(echo "$cat" | xargs)
        path=$(echo "$path" | xargs)
        path="${path/#\~/$HOME_DIR}"

        local expanded
        expanded=$(compgen -G "$path" 2>/dev/null || true)
        if [[ -n "$expanded" ]]; then
            while IFS= read -r p; do
                if [[ -f "$p" ]]; then
                    echo "$p"
                elif [[ -d "$p" ]]; then
                    find "$p" -type f 2>/dev/null
                fi
            done <<< "$expanded"
        fi
    done < "$CONFIG_FILE"
}

# Файлы которые сейчас временно разблокированы (guard unlock ставит метку)
is_temporarily_unlocked() {
    local filepath="$1"
    # Проверяем по логу — если unlock был менее 5 минут назад
    local five_min_ago
    five_min_ago=$(date -v-5M '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -d '5 minutes ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
    [[ -z "$five_min_ago" ]] && return 1

    if grep -q "\[ALLOW\].*unlock" "$LOG_FILE" 2>/dev/null; then
        local last_unlock
        last_unlock=$(grep "\[ALLOW\].*unlock" "$LOG_FILE" | tail -1 | cut -d' ' -f1-2)
        if [[ "$last_unlock" > "$five_min_ago" ]]; then
            return 0
        fi
    fi
    return 1
}


# ─── Claude Code config audit ───
# Хранит хеш последнего проверенного состояния чтобы не спамить алертами
CLAUDE_LAST_HASH=""

# Опасные wildcard-разрешения: ассистент может делать ВСЁ без подтверждения
CLAUDE_DANGEROUS_WILDCARDS=("Bash(*)" "Edit(*)" "Write(*)" "Bash(sudo")

# Опасные конкретные команды
CLAUDE_DANGEROUS_COMMANDS=(
    "Bash(rm " "Bash(curl " "Bash(wget " "Bash(chmod " "Bash(chown "
    "Bash(kill " "Bash(pkill " "Bash(launchctl " "Bash(defaults write"
    "Bash(osascript" "Bash(security " "Bash(ssh " "Bash(scp "
    "Bash(git push" "Bash(git reset" "Bash(npm publish" "Bash(npx "
    "Bash(open " "Bash(networksetup" "Bash(dscl " "Bash(crontab"
)

check_claude_configs() {
    local config_files=()

    # Собрать все конфиги Claude Code
    [[ -f "$HOME_DIR/.claude/settings.json" ]] && config_files+=("$HOME_DIR/.claude/settings.json")

    # Проектные конфиги (могут быть подброшены через PR)
    while IFS= read -r pfile; do
        [[ -n "$pfile" ]] && config_files+=("$pfile")
    done < <(find "$HOME_DIR/work" "$HOME_DIR/projects" "$HOME_DIR/Developer" \
        -maxdepth 4 \( -path "*/.claude/settings.json" -o -path "*/.claude/settings.local.json" \) \
        2>/dev/null || true)

    [[ ${#config_files[@]} -eq 0 ]] && return 0

    # Хеш текущего состояния — если не изменилось, не проверяем
    local current_hash
    current_hash=$(cat "${config_files[@]}" 2>/dev/null | shasum -a 256 | awk '{print $1}')
    if [[ "$current_hash" == "$CLAUDE_LAST_HASH" ]]; then
        return 0
    fi
    CLAUDE_LAST_HASH="$current_hash"

    log_event "CLAUDE_AUDIT: config change detected, scanning ${#config_files[@]} files"

    for config_path in "${config_files[@]}"; do
        local content
        content=$(cat "$config_path" 2>/dev/null) || continue

        local is_project=0
        [[ "$config_path" != "$HOME_DIR/.claude/settings.json" ]] && is_project=1

        # 1. Wildcard-разрешения — отдельный алерт на каждый
        for wc in "${CLAUDE_DANGEROUS_WILDCARDS[@]}"; do
            if echo "$content" | grep -qF "$wc"; then
                log_event "CLAUDE_CRITICAL: $config_path — wildcard: $wc"
                alert_user "Claude Config ALARM\n\nФайл: $config_path\nНайдено: $wc\n\nАссистент может выполнять любые действия этого типа без подтверждения!"
            fi
        done

        # 2. Опасные команды — алерт с перечислением найденных
        local found_cmds=""
        for cmd in "${CLAUDE_DANGEROUS_COMMANDS[@]}"; do
            if echo "$content" | grep -qF "$cmd"; then
                found_cmds="${found_cmds}${cmd}...\n"
                log_event "CLAUDE_WARN: $config_path — dangerous: $cmd"
            fi
        done
        if [[ -n "$found_cmds" ]]; then
            alert_user "Claude Config: опасные разрешения\n\nФайл: $config_path\nКоманды без подтверждения:\n$found_cmds\nЗапусти guard audit для деталей."
        fi

        # 3. Проектный конфиг с permissions/hooks — вектор атаки
        if [[ $is_project -eq 1 ]]; then
            if echo "$content" | grep -qE '"(allowedTools|permissions|allow)"'; then
                if echo "$content" | grep -qE '"Bash\((rm|curl|wget|chmod|sudo|kill|ssh|osascript|launchctl|security|defaults)'; then
                    log_event "CLAUDE_CRITICAL: project config with dangerous permissions: $config_path"
                    alert_user "Claude Config ALARM\n\nФайл: $config_path\nПроектный конфиг содержит опасные Bash-разрешения!\n\nМог быть подброшен через PR/commit."
                fi
            fi
            if echo "$content" | grep -qE '"hooks"'; then
                log_event "CLAUDE_CRITICAL: project config with hooks: $config_path"
                alert_user "Claude Config ALARM\n\nФайл: $config_path\nПроектный конфиг содержит hooks!\n\nHooks выполняют shell-команды автоматически.\nМог быть подброшен через PR/commit."
            fi
        fi
    done
}

log_event "FileGuard daemon started (interval: ${CHECK_INTERVAL}s)"

cycle_count=0
while true; do
    # ─── Проверка защищённых файлов (каждые 30 сек) ───
    files=$(get_all_protected_files)

    if [[ -n "$files" ]]; then
        while IFS= read -r filepath; do
            [[ -z "$filepath" || ! -e "$filepath" ]] && continue

            owner=$(stat -f '%Su' "$filepath" 2>/dev/null || echo "unknown")
            perms=$(stat -f '%Lp' "$filepath" 2>/dev/null || echo "000")

            # Файл должен принадлежать root с permissions 600
            if [[ "$owner" != "root" ]]; then
                # Проверить — может это временный unlock
                if is_temporarily_unlocked "$filepath"; then
                    continue
                fi

                # Несанкционированное изменение!
                log_event "ALARM: $filepath owned by $owner (expected root), permissions $perms — restoring"
                alert_user "Несанкционированное изменение!\n\n$filepath\nВладелец: $owner (должен быть root)\n\nВосстанавливаю защиту."

                chown root:wheel "$filepath"
                chmod 600 "$filepath"
            fi
        done <<< "$files"
    fi

    # ─── Аудит конфигов Claude Code (каждые 60 сек = каждый 2-й цикл) ───
    ((cycle_count++)) || true
    if (( cycle_count % 2 == 0 )); then
        check_claude_configs
    fi

    sleep "$CHECK_INTERVAL"
done
