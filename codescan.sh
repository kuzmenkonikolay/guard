#!/bin/bash
# CodeScan — проверка кода на подозрительные паттерны после git pull / checkout
# Сканирует diff между старым и новым состоянием

GUARD_DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || readlink "$0" 2>/dev/null || echo "$0")")" && pwd)"
LOG_FILE="$GUARD_DIR/logs/codescan.log"
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CODESCAN] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# ─── Загрузка паттернов из внешнего файла ───
# Паттерны хранятся в patterns.dat чтобы codescan.sh не содержал
# строки-сигнатуры и мог сканировать сам себя без false positives

PATTERNS_FILE="$GUARD_DIR/patterns.dat"
CRITICAL_PATTERNS=()
SUSPICIOUS_PATTERNS=()
SUSPICIOUS_CONFIG_FILES=()

load_patterns() {
    if [[ ! -f "$PATTERNS_FILE" ]]; then
        echo -e "${RED}patterns.dat не найден! Сканирование невозможно.${NC}"
        exit 1
    fi
    while IFS='|' read -r level pattern comment; do
        [[ "$level" =~ ^#.*$ || -z "$level" ]] && continue
        # Trim whitespace без xargs (xargs ломается на \x27)
        level="${level#"${level%%[![:space:]]*}"}"
        level="${level%"${level##*[![:space:]]}"}"
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        [[ -z "$pattern" ]] && continue
        case "$level" in
            critical)   CRITICAL_PATTERNS+=("$pattern") ;;
            suspicious) SUSPICIOUS_PATTERNS+=("$pattern") ;;
            config)     SUSPICIOUS_CONFIG_FILES+=("$pattern") ;;
        esac
    done < "$PATTERNS_FILE"
}

load_patterns

# ─── Детектор обфускации (эвристики) ───

# Обфусцированный код отличается от нормального по метрикам:
# - Очень длинные строки (>500 символов без пробелов)
# - Высокая плотность спецсимволов относительно букв
# - Массивы с большим количеством закодированных строк
# - Переменные из 1-2 символов в большом количестве
# - Строки в hex/unicode/base64 длиннее 100 символов

check_obfuscation() {
    local file="$1"
    local file_content="$2"
    local score=0
    local reasons=""

    # 1. Строки длиннее 500 символов (непрерывных, без пробелов)
    local long_lines
    long_lines=$(echo "$file_content" | awk 'length > 500 { count++ } END { print count+0 }')
    if [[ $long_lines -gt 3 ]]; then
        ((score += 30))
        reasons="${reasons}\n    - $long_lines строк длиннее 500 символов"
    fi

    # 2. Строки длиннее 1000 символов — почти наверняка обфускация или минификация
    local very_long_lines
    very_long_lines=$(echo "$file_content" | awk 'length > 1000 { count++ } END { print count+0 }')
    if [[ $very_long_lines -gt 0 ]]; then
        ((score += 40))
        reasons="${reasons}\n    - $very_long_lines строк длиннее 1000 символов"
    fi

    # 3. Высокая концентрация hex-последовательностей (\x41\x42...)
    local hex_count
    hex_count=$(echo "$file_content" | grep -oE '\\x[0-9a-fA-F]{2}' | wc -l | xargs)
    if [[ $hex_count -gt 20 ]]; then
        ((score += 40))
        reasons="${reasons}\n    - $hex_count hex-последовательностей (\\xNN)"
    fi

    # 4. Высокая концентрация unicode-последовательностей (\u0041...)
    local unicode_count
    unicode_count=$(echo "$file_content" | grep -oE '\\u[0-9a-fA-F]{4}' | wc -l | xargs)
    if [[ $unicode_count -gt 20 ]]; then
        ((score += 40))
        reasons="${reasons}\n    - $unicode_count unicode-последовательностей (\\uNNNN)"
    fi

    # 5. Base64 строки длиннее 100 символов
    local b64_count
    b64_count=$(echo "$file_content" | grep -oE '[A-Za-z0-9+/]{100,}={0,2}' | wc -l | xargs)
    if [[ $b64_count -gt 0 ]]; then
        ((score += 35))
        reasons="${reasons}\n    - $b64_count base64-строк длиннее 100 символов"
    fi

    # 6. Большой массив строк/чисел (типичная обфускация: _$_1e42 = ["...", "...", ...])
    local big_array
    big_array=$(echo "$file_content" | grep -cE '\[("[^"]{1,50}"\s*,\s*){10,}' 2>/dev/null) || big_array=0
    if [[ $big_array -gt 0 ]]; then
        ((score += 35))
        reasons="${reasons}\n    - Массив с 10+ закодированными строками (типичная обфускация)"
    fi

    # 7. Много однобуквенных переменных (var a=, let b=, const c=)
    local short_vars
    short_vars=$(echo "$file_content" | grep -oE '(var|let|const)\s+[a-zA-Z_$]{1,2}\s*=' | wc -l | xargs)
    local total_lines
    total_lines=$(echo "$file_content" | wc -l | xargs)
    if [[ $total_lines -gt 0 && $short_vars -gt 0 ]]; then
        local ratio=$((short_vars * 100 / total_lines))
        if [[ $ratio -gt 30 ]]; then
            ((score += 25))
            reasons="${reasons}\n    - ${ratio}% строк содержат однобуквенные переменные"
        fi
    fi

    # 8. Высокая энтропия — много спецсимволов относительно букв
    local special_chars
    special_chars=$(echo "$file_content" | tr -cd '[](){}!@#$%^&*~|\\' | wc -c | xargs)
    local alpha_chars
    alpha_chars=$(echo "$file_content" | tr -cd 'a-zA-Z' | wc -c | xargs)
    if [[ $alpha_chars -gt 0 ]]; then
        local spec_ratio=$((special_chars * 100 / alpha_chars))
        if [[ $spec_ratio -gt 60 ]]; then
            ((score += 30))
            reasons="${reasons}\n    - Высокая плотность спецсимволов (${spec_ratio}% от букв)"
        fi
    fi

    # 9. String.fromCharCode в большом количестве
    local charcode_count
    charcode_count=$(echo "$file_content" | grep -oE 'String\.fromCharCode|fromCharCode' | wc -l | xargs)
    if [[ $charcode_count -gt 5 ]]; then
        ((score += 30))
        reasons="${reasons}\n    - $charcode_count вызовов fromCharCode"
    fi

    # 10. Конкатенация строк для скрытия ключевых слов ("ch"+"ild_"+"proc"+"ess")
    local concat_suspicious
    concat_suspicious=$(echo "$file_content" | grep -cE '"[a-z]{1,4}"\s*\+\s*"[a-z]{1,4}"\s*\+\s*"[a-z]{1,4}"' 2>/dev/null) || concat_suspicious=0
    if [[ $concat_suspicious -gt 3 ]]; then
        ((score += 25))
        reasons="${reasons}\n    - $concat_suspicious цепочек конкатенации коротких строк (скрытие ключевых слов)"
    fi

    # Вывод результата
    if [[ $score -ge 60 ]]; then
        echo -e "${RED}!!!  ОБФУСКАЦИЯ ОБНАРУЖЕНА: $file (score: $score/100)${NC}"
        echo -e "${RED}     Признаки:${reasons}${NC}"
        log_event "OBFUSCATION score=$score file=$file"
        return 1
    elif [[ $score -ge 30 ]]; then
        echo -e "${YELLOW}  ⚠ Возможная обфускация: $file (score: $score/100)${NC}"
        echo -e "${YELLOW}    Признаки:${reasons}${NC}"
        log_event "OBFUSCATION_WARN score=$score file=$file"
        return 2
    fi
    return 0
}

# ─── Функции сканирования ───

scan_diff() {
    local old_ref="$1"
    local new_ref="$2"
    local changed_files
    local alerts=0
    local critical=0

    # Получить список изменённых файлов
    if [[ -n "$old_ref" && -n "$new_ref" ]]; then
        changed_files=$(git diff --name-only "$old_ref" "$new_ref" 2>/dev/null)
    else
        # Fallback — последний коммит
        changed_files=$(git diff --name-only HEAD~1 HEAD 2>/dev/null)
    fi

    [[ -z "$changed_files" ]] && return 0

    local total_files
    total_files=$(echo "$changed_files" | wc -l | xargs)

    echo -e "${YELLOW}[CodeScan] Проверяю $total_files изменённых файлов...${NC}"

    # Проверить каждый файл
    while IFS= read -r file; do
        [[ -z "$file" || ! -f "$file" ]] && continue

        # Пропустить бинарники, картинки, шрифты
        case "$file" in
            *.png|*.jpg|*.jpeg|*.gif|*.ico|*.woff|*.woff2|*.ttf|*.eot|*.mp4|*.webm|*.zip|*.tar|*.gz) continue ;;
            *.min.js|*.min.css|*.map) continue ;;  # минифицированные файлы
            node_modules/*|vendor/*|.git/*|*/patterns.dat) continue ;;
        esac

        local file_content
        file_content=$(cat "$file" 2>/dev/null) || continue

        # Критические паттерны
        for pattern in "${CRITICAL_PATTERNS[@]}"; do
            local matches
            matches=$(echo "$file_content" | grep -nE "$pattern" 2>/dev/null)
            if [[ -n "$matches" ]]; then
                ((critical++))
                ((alerts++))
                echo ""
                echo -e "${RED}!!!  КРИТИЧЕСКОЕ СОВПАДЕНИЕ в $file${NC}"
                echo -e "${RED}     Паттерн: $pattern${NC}"
                echo "$matches" | head -3 | while IFS= read -r line; do
                    echo -e "  ${RED}> $line${NC}"
                done
                log_event "CRITICAL: $file pattern=$pattern"
            fi
        done

        # Подозрительные паттерны
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            local matches
            matches=$(echo "$file_content" | grep -nE "$pattern" 2>/dev/null)
            if [[ -n "$matches" ]]; then
                ((alerts++))
                echo -e "${YELLOW}  ⚠ $file — совпадение: $pattern${NC}"
                echo "$matches" | head -2 | while IFS= read -r line; do
                    echo -e "    ${YELLOW}> $line${NC}"
                done
                log_event "SUSPICIOUS: $file pattern=$pattern"
            fi
        done

        # Проверка конфиг-файлов на подозрительную логику
        local basename
        basename=$(basename "$file")
        for config in "${SUSPICIOUS_CONFIG_FILES[@]}"; do
            if [[ "$basename" == "$config" ]]; then
                # Конфиг не должен содержать eval, fetch, require('child_process'), Buffer.from
                local config_danger
                config_danger=$(echo "$file_content" | grep -nE '(eval\s*\(|child_process|\.exec\s*\(|Buffer\.from|fetch\s*\(.*http|new\s+Function)' 2>/dev/null)
                if [[ -n "$config_danger" ]]; then
                    ((critical++))
                    ((alerts++))
                    echo ""
                    echo -e "${RED}!!!  ОПАСНЫЙ КОД В КОНФИГЕ: $file${NC}"
                    echo -e "${RED}     Конфиг-файлы не должны содержать такую логику!${NC}"
                    echo "$config_danger" | head -5 | while IFS= read -r line; do
                        echo -e "  ${RED}> $line${NC}"
                    done
                    log_event "CRITICAL CONFIG: $file"
                fi
            fi
        done

        # Детектор обфускации (ловит новые/неизвестные обфускации)
        if check_obfuscation "$file" "$file_content"; then
            : # чисто
        else
            local obf_result=$?
            if [[ $obf_result -eq 1 ]]; then
                ((critical++))
                ((alerts++))
            elif [[ $obf_result -eq 2 ]]; then
                ((alerts++))
            fi
        fi

    done <<< "$changed_files"

    # Проверить package.json на подозрительные скрипты
    if echo "$changed_files" | grep -q "package.json"; then
        local pkg_scripts
        pkg_scripts=$(cat package.json 2>/dev/null | grep -E '"(preinstall|postinstall|prepack|prepare)"' | grep -E '(curl|wget|node\s+-e|sh\s+-c|bash\s+-c)' 2>/dev/null)
        if [[ -n "$pkg_scripts" ]]; then
            ((critical++))
            ((alerts++))
            echo ""
            echo -e "${RED}!!!  ПОДОЗРИТЕЛЬНЫЕ СКРИПТЫ В package.json${NC}"
            echo "$pkg_scripts" | while IFS= read -r line; do
                echo -e "  ${RED}> $line${NC}"
            done
            log_event "CRITICAL: package.json suspicious scripts"
        fi
    fi

    # Итог
    echo ""
    if [[ $critical -gt 0 ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  НАЙДЕНО $critical КРИТИЧЕСКИХ СОВПАДЕНИЙ!         ║${NC}"
        echo -e "${RED}║  НЕ ЗАПУСКАЙ ЭТОТ КОД ДО ПРОВЕРКИ!          ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"

        osascript -e "display dialog \"CodeScan: НАЙДЕНО $critical КРИТИЧЕСКИХ СОВПАДЕНИЙ!\n\nНе запускай код до ручной проверки.\nСмотри терминал для деталей.\" buttons {\"OK\"} default button \"OK\" with icon stop with title \"CodeScan ALARM\"" 2>/dev/null || true

        log_event "SCAN COMPLETE: $critical critical, $alerts total alerts"
        return 1

    elif [[ $alerts -gt 0 ]]; then
        echo -e "${YELLOW}[CodeScan] Найдено $alerts подозрительных совпадений. Проверь вручную.${NC}"
        log_event "SCAN COMPLETE: 0 critical, $alerts suspicious"
        return 0

    else
        echo -e "${GREEN}[CodeScan] Чисто. Подозрительных паттернов не найдено.${NC}"
        log_event "SCAN COMPLETE: clean ($total_files files checked)"
        return 0
    fi
}

# ─── Точки входа ───

# Вызов из git hook (post-merge)
hook_post_merge() {
    local old_head="$1"
    scan_diff "$old_head" "HEAD"
}

# Вызов из git hook (post-checkout)
hook_post_checkout() {
    local old_ref="$1"
    local new_ref="$2"
    local branch_checkout="$3"

    # Только при смене ветки, не при checkout файла
    [[ "$branch_checkout" != "1" ]] && return 0

    scan_diff "$old_ref" "$new_ref"
}

# Ручной вызов — сканировать весь проект
scan_full() {
    local dir="${1:-.}"
    echo -e "${YELLOW}[CodeScan] Полное сканирование: $dir${NC}"

    local all_files
    all_files=$(find "$dir" -type f \( -name '*.js' -o -name '*.ts' -o -name '*.jsx' -o -name '*.tsx' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.json' -o -name '*.rb' -o -name '*.py' -o -name '*.sh' \) \
        -not -path '*/node_modules/*' \
        -not -path '*/.git/*' \
        -not -path '*/vendor/*' \
        -not -path '*/dist/*' \
        -not -path '*/build/*' \
        -not -path '*/.next/*' \
        -not -path '*/patterns.dat' \
        2>/dev/null)

    [[ -z "$all_files" ]] && echo "Нет файлов для проверки." && return 0

    # Подставляем как будто это changed_files
    local total
    total=$(echo "$all_files" | wc -l | xargs)
    echo -e "${YELLOW}[CodeScan] Проверяю $total файлов...${NC}"

    # Используем ту же логику что и scan_diff но по всем файлам
    local alerts=0 critical=0

    while IFS= read -r file; do
        [[ -z "$file" || ! -f "$file" ]] && continue

        local file_content
        file_content=$(cat "$file" 2>/dev/null) || continue

        for pattern in "${CRITICAL_PATTERNS[@]}"; do
            local matches
            matches=$(echo "$file_content" | grep -nE "$pattern" 2>/dev/null)
            if [[ -n "$matches" ]]; then
                ((critical++))
                ((alerts++))
                echo -e "${RED}!!!  КРИТИЧЕСКОЕ: $file — $pattern${NC}"
                echo "$matches" | head -3 | while IFS= read -r line; do
                    echo -e "  ${RED}> $line${NC}"
                done
            fi
        done

        local basename
        basename=$(basename "$file")
        for config in "${SUSPICIOUS_CONFIG_FILES[@]}"; do
            if [[ "$basename" == "$config" ]]; then
                local config_danger
                config_danger=$(echo "$file_content" | grep -nE '(eval\s*\(|child_process|\.exec\s*\(|Buffer\.from|fetch\s*\(.*http|new\s+Function)' 2>/dev/null)
                if [[ -n "$config_danger" ]]; then
                    ((critical++))
                    echo -e "${RED}!!!  ОПАСНЫЙ КОНФИГ: $file${NC}"
                    echo "$config_danger" | head -3 | while IFS= read -r line; do
                        echo -e "  ${RED}> $line${NC}"
                    done
                fi
            fi
        done

        # Детектор обфускации
        if check_obfuscation "$file" "$file_content"; then
            : # чисто
        else
            local obf_result=$?
            if [[ $obf_result -eq 1 ]]; then
                ((critical++))
            fi
        fi

    done <<< "$all_files"

    echo ""
    if [[ $critical -gt 0 ]]; then
        echo -e "${RED}НАЙДЕНО $critical КРИТИЧЕСКИХ СОВПАДЕНИЙ!${NC}"
    else
        echo -e "${GREEN}[CodeScan] Чисто. ($total файлов проверено)${NC}"
    fi
}

# ─── Main ───
case "${1:-}" in
    post-merge)    hook_post_merge "$2" ;;
    post-checkout) hook_post_checkout "$2" "$3" "$4" ;;
    scan)          scan_full "${2:-.}" ;;
    *)
        echo "CodeScan — проверка кода на подозрительные паттерны"
        echo ""
        echo "Использование:"
        echo "  codescan.sh scan [path]         Полное сканирование проекта"
        echo "  codescan.sh post-merge <old>    Git hook: после pull"
        echo "  codescan.sh post-checkout ...   Git hook: после checkout"
        ;;
esac
