#!/bin/bash
# ProcessGuard — мониторинг подозрительных процессов
# Запускается как LaunchAgent от пользователя
# Каждые 2 секунды сканирует новые процессы

GUARD_DIR="$(cd "$(dirname "$0")" && pwd)"
WHITELIST_FILE="$GUARD_DIR/whitelist-procs"
LOG_FILE="$GUARD_DIR/logs/process.log"
SCAN_INTERVAL=2

# Хранение известных PID
declare -A KNOWN_PIDS
declare -A ALERTED_PIDS

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [PROCGUARD] $1" >> "$LOG_FILE"
}

# Загрузить whitelist
declare -A WHITELIST_NAMES
declare -A WHITELIST_PATHS

load_whitelist() {
    while IFS='|' read -r name path args; do
        [[ "$name" =~ ^#.*$ || -z "$name" ]] && continue
        name=$(echo "$name" | xargs)
        path=$(echo "$path" | xargs)
        WHITELIST_NAMES["$name"]=1
        if [[ -n "$path" ]]; then
            WHITELIST_PATHS["${name}|${path}"]=1
        fi
    done < "$WHITELIST_FILE"
}

# Проверить подозрительные паттерны в аргументах процесса
is_suspicious_args() {
    local args="$1"

    # node -e "..." — именно так запускался Beavertail
    if echo "$args" | grep -qE 'node\s+-e\s+'; then
        return 0
    fi

    # python -c "..."
    if echo "$args" | grep -qE 'python[23]?\s+-c\s+'; then
        return 0
    fi

    # curl/wget piped to shell
    if echo "$args" | grep -qE '(curl|wget)\s+.*\|\s*(sh|bash|zsh|node|python)'; then
        return 0
    fi

    # eval with base64
    if echo "$args" | grep -qE '(eval|exec)\s*\(.*base64'; then
        return 0
    fi

    # nohup с подозрительным payload
    if echo "$args" | grep -qE 'nohup\s+.*(curl|wget|node\s+-e|python\s+-c)'; then
        return 0
    fi

    return 1
}

# Проверить процесс по whitelist
is_whitelisted() {
    local proc_name="$1"
    local proc_path="$2"

    # Проверить имя
    if [[ -z "${WHITELIST_NAMES[$proc_name]+x}" ]]; then
        return 1  # не в whitelist
    fi

    # Если есть ограничение по пути — проверить
    local found_path_match=0
    local has_path_rules=0

    for key in "${!WHITELIST_PATHS[@]}"; do
        local wl_name="${key%%|*}"
        local wl_path="${key##*|}"
        if [[ "$wl_name" == "$proc_name" ]]; then
            has_path_rules=1
            if [[ "$proc_path" == "$wl_path"* ]]; then
                found_path_match=1
                break
            fi
        fi
    done

    if [[ $has_path_rules -eq 1 && $found_path_match -eq 0 ]]; then
        return 1  # есть правила по пути, но путь не совпал
    fi

    return 0
}

# Показать диалог и обработать ответ
handle_suspicious_process() {
    local pid="$1"
    local proc_name="$2"
    local proc_args="$3"
    local ppid="$4"
    local parent_name="$5"

    # Проверить сетевые соединения процесса
    local net_info
    net_info=$(lsof -i -a -p "$pid" 2>/dev/null | tail -5 | head -3 || echo "нет подключений")

    local dialog_text="Подозрительный процесс обнаружен!

PID: $pid
Процесс: $proc_name
Аргументы: ${proc_args:0:200}
Родитель: $parent_name (PID $ppid)
Сеть: $net_info"

    log_event "SUSPICIOUS: PID=$pid name=$proc_name args=${proc_args:0:500} parent=$parent_name($ppid)"

    local result
    result=$(osascript -e "
        display dialog \"$dialog_text\" buttons {\"Kill Process\", \"Allow Once\", \"Add to Whitelist\"} default button \"Kill Process\" with icon stop with title \"ProcessGuard\" giving up after 30
    " 2>/dev/null) || result="button returned:Kill Process"

    if [[ "$result" == *"Kill Process"* ]]; then
        kill -9 "$pid" 2>/dev/null || true
        log_event "KILLED: PID=$pid name=$proc_name"
        osascript -e "display notification \"Процесс $proc_name (PID $pid) убит\" with title \"ProcessGuard\"" 2>/dev/null || true

    elif [[ "$result" == *"Add to Whitelist"* ]]; then
        echo "$proc_name||" >> "$WHITELIST_FILE"
        WHITELIST_NAMES["$proc_name"]=1
        log_event "WHITELISTED: name=$proc_name"
        osascript -e "display notification \"$proc_name добавлен в whitelist\" with title \"ProcessGuard\"" 2>/dev/null || true

    else
        # Allow Once
        ALERTED_PIDS["$pid"]=1
        log_event "ALLOWED_ONCE: PID=$pid name=$proc_name"
    fi
}

# ─── Main loop ───
log_event "ProcessGuard daemon started (interval: ${SCAN_INTERVAL}s)"
load_whitelist

# Инициализация — запомнить текущие процессы
while IFS= read -r line; do
    local_pid=$(echo "$line" | awk '{print $1}')
    KNOWN_PIDS["$local_pid"]=1
done < <(ps -axo pid= 2>/dev/null)

while true; do
    # Получить текущий список процессов с деталями
    while IFS= read -r line; do
        pid=$(echo "$line" | awk '{print $1}')
        ppid=$(echo "$line" | awk '{print $2}')
        proc_path=$(echo "$line" | awk '{print $3}')
        proc_name=$(basename "$proc_path" 2>/dev/null || echo "$proc_path")
        proc_args=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}')

        # Пропустить уже известные PID
        if [[ -n "${KNOWN_PIDS[$pid]+x}" ]]; then
            continue
        fi

        # Пропустить уже alertнутые
        if [[ -n "${ALERTED_PIDS[$pid]+x}" ]]; then
            continue
        fi

        # Запомнить PID
        KNOWN_PIDS["$pid"]=1

        # Пропустить самого себя и системные
        if [[ "$pid" == "$$" || "$pid" == "1" ]]; then
            continue
        fi

        # Пропустить процессы без имени
        if [[ -z "$proc_name" || "$proc_name" == "-" ]]; then
            continue
        fi

        # Проверка 1: подозрительные аргументы (всегда алерт, даже если в whitelist)
        if is_suspicious_args "$proc_args"; then
            local parent_name
            parent_name=$(ps -p "$ppid" -o comm= 2>/dev/null || echo "unknown")
            handle_suspicious_process "$pid" "$proc_name" "$proc_args" "$ppid" "$parent_name"
            continue
        fi

        # Проверка 2: не в whitelist
        if ! is_whitelisted "$proc_name" "$proc_path"; then
            # Проверить есть ли сетевые подключения (подозрительнее)
            local has_net
            has_net=$(lsof -i -a -p "$pid" 2>/dev/null | wc -l || echo 0)

            if [[ "$has_net" -gt 0 ]]; then
                local parent_name
                parent_name=$(ps -p "$ppid" -o comm= 2>/dev/null || echo "unknown")
                handle_suspicious_process "$pid" "$proc_name" "$proc_args" "$ppid" "$parent_name"
            fi
        fi

    done < <(ps -axo pid=,ppid=,comm= 2>/dev/null | tail -n +2)

    # Очистка мёртвых PID из памяти (каждые 60 секунд)
    if (( SECONDS % 60 < SCAN_INTERVAL )); then
        local active_pids
        active_pids=$(ps -axo pid= 2>/dev/null | tr -d ' ')
        for known_pid in "${!KNOWN_PIDS[@]}"; do
            if ! echo "$active_pids" | grep -q "^${known_pid}$"; then
                unset "KNOWN_PIDS[$known_pid]"
                unset "ALERTED_PIDS[$known_pid]" 2>/dev/null || true
            fi
        done
    fi

    sleep "$SCAN_INTERVAL"
done
