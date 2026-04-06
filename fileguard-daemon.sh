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

log_event "FileGuard daemon started (interval: ${CHECK_INTERVAL}s)"

while true; do
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

    sleep "$CHECK_INTERVAL"
done
