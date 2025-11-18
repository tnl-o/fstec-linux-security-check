#!/bin/bash

# Скрипт проверки рекомендаций ФСТЭК по безопасной настройке ОС Linux
# Выводит результаты проверки в формате: [OK] - соответствует, [FAIL] - не соответствует, [N/A] - не применимо
#
# Версия: 1.0.0
# Автор: FSTEC Linux Security Check Contributors
# Лицензия: MIT
# Репозиторий: https://github.com/yourusername/fstec-linux-security-check
#
# Основано на документе ФСТЭК России:
# "РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОЙ НАСТРОЙКЕ ОПЕРАЦИОННЫХ СИСТЕМ LINUX"
# Утвержден 25 декабря 2022 г.
# https://fstec.ru/documents/tekhnicheskaya-zashchita-informatsii/metodicheskie-dokumenty/751

# Цветовая подсветка и утилитарные функции вывода
GREEN=$'\033[32m'
RED=$'\033[31m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'
OK_LABEL="${GREEN}[OK]${RESET}"
FAIL_LABEL="${RED}[FAIL]${RESET}"
WARN_LABEL="${YELLOW}[WARN]${RESET}"
NA_LABEL="${YELLOW}[N/A]${RESET}"
REMEDY_LABEL="${YELLOW}[РЕКОМЕНДАЦИЯ]${RESET}"

print_status() {
    local label="$1"
    shift
    local message="$*"
    if [ -n "$message" ]; then
        echo "$message $label"
    else
        echo "$label"
    fi
}

ok()   { print_status "$OK_LABEL" "$@"; }
fail() { print_status "$FAIL_LABEL" "$@"; }
warn() { print_status "$WARN_LABEL" "$@"; }
na()   { print_status "$NA_LABEL" "$@"; }
recommend() { echo "${REMEDY_LABEL} $*"; }

echo "=== Чек-лист безопасности по рекомендациям ФСТЭК ==="
echo

# 2.1. Настройка авторизации
echo "2.1. Настройка авторизации в операционной системе Linux"
echo

# 2.1.1. Проверка учетных записей с пустыми паролями
if awk -F: '$2 == "" { print $1 }' /etc/shadow | grep -q .; then
    fail "2.1.1. Проверка учетных записей с пустыми паролями..."
else
    ok "2.1.1. Проверка учетных записей с пустыми паролями..."
fi

# 2.1.2. Проверка отключения входа root по SSH
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config || grep -q "^PermitRootLogin\s*no\b" /etc/ssh/sshd_config; then
    ok "2.1.2. Проверка отключения входа root по SSH..."
elif grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config || grep -q "^PermitRootLogin\s*yes\b" /etc/ssh/sshd_config; then
    fail "2.1.2. Проверка отключения входа root по SSH..."
else
    na "2.1.2. Проверка отключения входа root по SSH... [не настроено явно]"
fi
echo

# 2.2. Ограничение механизмов получения привилегий
echo "2.2. Ограничение механизмов получения привилегий"
echo

# 2.2.1. Проверка ограничения доступа к su
if grep -q "auth required pam_wheel.so use_uid" /etc/pam.d/su; then
    ok "2.2.1. Проверка ограничения доступа к команде su..."
else
    fail "2.2.1. Проверка ограничения доступа к команде su..."
fi

# 2.2.2. Проверка ограничения sudo (проверка наличия файла)
if [ -f /etc/sudoers ]; then
    ok "2.2.2. Проверка файла ограничений sudo /etc/sudoers... [файл существует, проверьте содержимое вручную]"
else
    fail "2.2.2. Проверка файла ограничений sudo /etc/sudoers... [файл отсутствует]"
fi
echo

# 2.3. Права доступа к объектам файловой системы
echo "2.3. Настройка прав доступа к объектам файловой системы"
echo

# 2.3.1. Проверка прав на /etc/passwd, /etc/group, /etc/shadow
if [ "$(stat -c %a /etc/passwd)" = "644" ]; then
    ok "2.3.1. Проверка прав на /etc/passwd... "
else
    fail "2.3.1. Проверка прав на /etc/passwd... "
fi

if [ "$(stat -c %a /etc/group)" = "644" ]; then
    ok "2.3.1. Проверка прав на /etc/group... "
else
    fail "2.3.1. Проверка прав на /etc/group... "
fi

shadow_perms=$(stat -c %a /etc/shadow)
if [ "${shadow_perms:2:1}" = "0" ] && [ "${shadow_perms:1:1}" = "0" ]; then # g=0, o=0
    ok "2.3.1. Проверка прав на /etc/shadow (go-rwx)... "
else
    fail "2.3.1. Проверка прав на /etc/shadow (go-rwx)... "
fi

# 2.3.2. Проверка прав на исполняемые файлы запущенных процессов (базовая проверка на /bin)
if [ -d /bin ] && [ -r /bin ] && [ "$(find /bin -perm -002 -type f 2>/dev/null | wc -l)" -eq 0 ]; then
    ok "2.3.2. Проверка прав на исполняемые файлы в /bin (go-w)... "
else
    fail "2.3.2. Проверка прав на исполняемые файлы в /bin (go-w)... "
fi

# 2.3.3. Проверка прав на файлы заданий cron (проверка директорий)
if [ -d /etc/cron.d ] && [ "$(find /etc/cron.d -perm -002 -type f 2>/dev/null | wc -l)" -eq 0 ]; then
    ok "2.3.3. Проверка прав на файлы заданий cron в /etc/cron.d/... "
else
    fail "2.3.3. Проверка прав на файлы заданий cron в /etc/cron.d/... "
fi

# 2.3.4. Проверка прав на исполняемые файлы для sudo (проверка владельца root и прав)
suid_with_wrong_owner_or_perms=$(find / -perm -4000 -type f -exec stat -c "%U %A %n" {} \; 2>/dev/null | awk '$1 != "root" || substr($2, 7, 1) == "w" || substr($2, 8, 1) == "w" { print $0 }')
if [ -z "$suid_with_wrong_owner_or_perms" ]; then
    ok "2.3.4. Проверка владельца и прав на исполняемые файлы с SUID bit... "
else
    fail "2.3.4. Проверка владельца и прав на исполняемые файлы с SUID bit... "
    # echo "$suid_with_wrong_owner_or_perms" # Для детального вывода
fi

# 2.3.5. Проверка прав на стартовые скрипты (проверка /etc/rc.d/ или /etc/init.d/)
if [ -d /etc/init.d ] && [ "$(find /etc/init.d -perm -002 -type f 2>/dev/null | wc -l)" -eq 0 ]; then
    ok "2.3.5. Проверка прав на стартовые скрипты в /etc/init.d/ (o-w)... "
else
    fail "2.3.5. Проверка прав на стартовые скрипты в /etc/init.d/ (o-w)... "
fi

# 2.3.6. Проверка прав на системные файлы cron
cron_sys_files="/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
all_ok=true
for file in $cron_sys_files; do
    if [ -e "$file" ] || [ -d "$file" ]; then
        perms=$(stat -c %a "$file")
        if [ "${perms:2:1}" != "0" ] || [ "${perms:1:1}" != "0" ]; then # g!=0 or o!=0
            all_ok=false
            break
        fi
    fi
done
if $all_ok; then
    ok "2.3.6. Проверка прав на системные файлы cron (go-wx)... "
else
    fail "2.3.6. Проверка прав на системные файлы cron (go-wx)... "
fi

# 2.3.7. Проверка прав на пользовательские файлы заданий cron (проверка для root)
if [ -d /var/spool/cron/crontabs ] && [ "$(find /var/spool/cron/crontabs -perm -002 -type f 2>/dev/null | wc -l)" -eq 0 ]; then
    ok "2.3.7. Проверка прав на пользовательские файлы cron (root)... "
else
    fail "2.3.7. Проверка прав на пользовательские файлы cron (root)... "
fi

# 2.3.8. Проверка прав на системные исполняемые файлы и библиотеки (базовая проверка)
path_dirs=$(echo $PATH | tr ':' '\n')
all_ok=true
for dir in $path_dirs; do
    if [ -d "$dir" ]; then
        if [ "$(find "$dir" -perm -002 -type f 2>/dev/null | wc -l)" -ne 0 ]; then
            all_ok=false
            break
        fi
    fi
done
if $all_ok; then
    ok "2.3.8. Проверка прав на системные исполняемые файлы (базовая)... "
else
    fail "2.3.8. Проверка прав на системные исполняемые файлы (базовая)... "
fi

# 2.3.9. Проверка SUID/SGID-приложений
suid_writable_by_others=$(find / -perm -4002 -o -perm -2002 -type f 2>/dev/null) # u+s,g+w or g+s,g+w
if [ -z "$suid_writable_by_others" ]; then
    ok "2.3.9. Проверка SUID/SGID-приложений (права на запись)... "
else
    fail "2.3.9. Проверка SUID/SGID-приложений (права на запись)... "
    # echo "$suid_writable_by_others" # Для детального вывода
fi

# === Доработка: 2.3.10 и 2.3.11 для всех пользователей ===
echo "2.3.10/2.3.11: Проверка прав на файлы истории и домашние директории для всех пользователей из /etc/passwd"
while IFS=: read -r username _ uid gid _ homedir shell; do
    # Пропускать системных и несуществующих пользователей
    if [ "$uid" -lt 1000 ] && [ "$username" != "root" ]; then continue; fi
    [ ! -d "$homedir" ] && continue
    ok_dir="true"
    if [ "$(stat -c %a "$homedir" 2>/dev/null)" != "700" ]; then
        ok_dir="false"
        fail "$username: Домашняя директория $homedir имеет права $(stat -c %a "$homedir") (ожидалось 700)"
    fi
    # Файлы истории/настроек
    filelist=(".bash_history" ".bash_profile" ".bashrc" ".profile" ".bash_logout" ".sh_history" ".history" ".rhosts")
    for fname in "${filelist[@]}"; do
        fpath="$homedir/$fname"
        [ -f "$fpath" ] || continue
        perms=$(stat -c %a "$fpath")
        if [ "${perms:2:1}" != "0" ] || [ "${perms:1:1}" != "0" ]; then
            ok_dir="false"
            fail "$username: $fpath имеет права $perms (ожидалось --- для group/other)"
        fi
    done
    if [ "$ok_dir" = "true" ]; then
        ok "$username: $homedir и файлы истории/настроек защищены"
    fi
done < /etc/passwd

# === Доработка: 2.2.2 подробный анализ sudoers ===
if [ -f /etc/sudoers ]; then
    bad_entries=$(awk '/^[^#]/ && $1!~/root/ && $0~/ALL/ {print $0}' /etc/sudoers)
    if [ -n "$bad_entries" ]; then
    fail "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): Обнаружены подозрительные строки:"
    echo "$bad_entries"
    else
        ok "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): Не найдено подозрительных разрешений кроме root"
    fi
    nopass_entries=$(awk '/^[^#]/ && $1!~/root/ && $0~/NOPASSWD/ {print $0}' /etc/sudoers)
    if [ -n "$nopass_entries" ]; then
        warn "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): Наличие NOPASSWD для не-root:"
        echo "$nopass_entries"
    fi
else
    fail "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): файл отсутствует"
fi
echo

# 2.4. Механизмы защиты ядра Linux
echo "2.4. Настройка механизмов защиты ядра Linux"
echo

# 2.4.1. Проверка dmesg_restrict
if [ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" = "1" ]; then
    ok "2.4.1. Проверка kernel.dmesg_restrict... "
else
    fail "2.4.1. Проверка kernel.dmesg_restrict... "
fi

# 2.4.2. Проверка kptr_restrict
if [ "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" = "2" ]; then
    ok "2.4.2. Проверка kernel.kptr_restrict... "
else
    fail "2.4.2. Проверка kernel.kptr_restrict... "
fi

# 2.4.3. Проверка init_on_alloc (проверка в параметрах загрузки)
if grep -q "init_on_alloc=1" /proc/cmdline; then
    ok "2.4.3. Проверка init_on_alloc в параметрах загрузки... "
else
    fail "2.4.3. Проверка init_on_alloc в параметрах загрузки... "
fi

# 2.4.4. Проверка slab_nomerge (проверка в параметрах загрузки)
if grep -q "slab_nomerge" /proc/cmdline; then
    ok "2.4.4. Проверка slab_nomerge в параметрах загрузки... "
else
    fail "2.4.4. Проверка slab_nomerge в параметрах загрузки... "
fi

# 2.4.5. Проверка IOMMU (проверка в параметрах загрузки)
if grep -q "iommu=force" /proc/cmdline && grep -q "iommu.strict=1" /proc/cmdline && grep -q "iommu.passthrough=0" /proc/cmdline; then
    ok "2.4.5. Проверка IOMMU в параметрах загрузки (iommu=force, iommu.strict=1, iommu.passthrough=0)... "
else
    fail "2.4.5. Проверка IOMMU в параметрах загрузки (iommu=force, iommu.strict=1, iommu.passthrough=0)... "
fi

# 2.4.6. Проверка randomize_kstack_offset (проверка в параметрах загрузки)
if grep -q "randomize_kstack_offset=1" /proc/cmdline; then
    ok "2.4.6. Проверка randomize_kstack_offset в параметрах загрузки... "
else
    fail "2.4.6. Проверка randomize_kstack_offset в параметрах загрузки... "
fi

# 2.4.7. Проверка mitigations (проверка в параметрах загрузки)
if grep -q "mitigations=auto,nosmt" /proc/cmdline; then
    ok "2.4.7. Проверка mitigations в параметрах загрузки... "
else
    fail "2.4.7. Проверка mitigations в параметрах загрузки... "
fi

# 2.4.8. Проверка bpf_jit_harden
if [ "$(sysctl -n net.core.bpf_jit_harden 2>/dev/null)" = "2" ]; then
    ok "2.4.8. Проверка net.core.bpf_jit_harden... "
else
    fail "2.4.8. Проверка net.core.bpf_jit_harden... "
fi
echo

# 2.5. Уменьшение периметра атаки ядра Linux
echo "2.5. Уменьшение периметра атаки ядра Linux"
echo

# 2.5.1. Проверка vsyscall (проверка в параметрах загрузки)
if grep -q "vsyscall=none" /proc/cmdline; then
    ok "2.5.1. Проверка vsyscall в параметрах загрузки... "
else
    fail "2.5.1. Проверка vsyscall в параметрах загрузки... "
fi

# 2.5.2. Проверка perf_event_paranoid
if [ "$(sysctl -n kernel.perf_event_paranoid 2>/dev/null)" = "3" ]; then
    ok "2.5.2. Проверка kernel.perf_event_paranoid... "
else
    fail "2.5.2. Проверка kernel.perf_event_paranoid... "
fi

# 2.5.3. Проверка debugfs (проверка в параметрах загрузки) - сложно проверить монтирование напрямую
if grep -q "debugfs=no-mount\|debugfs=off" /proc/cmdline; then
    ok "2.5.3. Проверка debugfs в параметрах загрузки (предполагаем)... "
else
    fail "2.5.3. Проверка debugfs в параметрах загрузки (предполагаем)... "
fi

# 2.5.4. Проверка kexec_load_disabled
if [ "$(sysctl -n kernel.kexec_load_disabled 2>/dev/null)" = "1" ]; then
    ok "2.5.4. Проверка kernel.kexec_load_disabled... "
else
    fail "2.5.4. Проверка kernel.kexec_load_disabled... "
fi

# 2.5.5. Проверка max_user_namespaces
if [ "$(sysctl -n user.max_user_namespaces 2>/dev/null)" = "0" ]; then
    ok "2.5.5. Проверка user.max_user_namespaces... "
else
    fail "2.5.5. Проверка user.max_user_namespaces... "
fi

# 2.5.6. Проверка unprivileged_bpf_disabled
if [ "$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)" = "1" ]; then
    ok "2.5.6. Проверка kernel.unprivileged_bpf_disabled... "
else
    fail "2.5.6. Проверка kernel.unprivileged_bpf_disabled... "
fi

# 2.5.7. Проверка unprivileged_userfaultfd
if [ "$(sysctl -n vm.unprivileged_userfaultfd 2>/dev/null)" = "0" ]; then
    ok "2.5.7. Проверка vm.unprivileged_userfaultfd... "
else
    fail "2.5.7. Проверка vm.unprivileged_userfaultfd... "
fi

# 2.5.8. Проверка ldisc_autoload
if [ "$(sysctl -n dev.tty.ldisc_autoload 2>/dev/null)" = "0" ]; then
    ok "2.5.8. Проверка dev.tty.ldisc_autoload... "
else
    fail "2.5.8. Проверка dev.tty.ldisc_autoload... "
fi

# 2.5.9. Проверка TSX (проверка в параметрах загрузки)
if grep -q "tsx=off" /proc/cmdline; then
    ok "2.5.9. Проверка tsx=off в параметрах загрузки... "
else
    fail "2.5.9. Проверка tsx=off в параметрах загрузки... "
fi

# 2.5.10. Проверка mmap_min_addr
min_addr=$(sysctl -n vm.mmap_min_addr 2>/dev/null)
if [ "$min_addr" -ge 4096 ] 2>/dev/null; then
    ok "2.5.10. Проверка vm.mmap_min_addr... "
else
    fail "2.5.10. Проверка vm.mmap_min_addr... "
fi

# 2.5.11. Проверка randomize_va_space
if [ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = "2" ]; then
    ok "2.5.11. Проверка kernel.randomize_va_space... "
else
    fail "2.5.11. Проверка kernel.randomize_va_space... "
fi
echo

# 2.6. Средства защиты пользовательского пространства
echo "2.6. Настройка средств защиты пользовательского пространства со стороны ядра Linux"
echo

# 2.6.1. Проверка ptrace_scope
if [ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" = "3" ]; then
    ok "2.6.1. Проверка kernel.yama.ptrace_scope... "
else
    fail "2.6.1. Проверка kernel.yama.ptrace_scope... "
fi

# 2.6.2. Проверка protected_symlinks
if [ "$(sysctl -n fs.protected_symlinks 2>/dev/null)" = "1" ]; then
    ok "2.6.2. Проверка fs.protected_symlinks... "
else
    fail "2.6.2. Проверка fs.protected_symlinks... "
fi

# 2.6.3. Проверка protected_hardlinks
if [ "$(sysctl -n fs.protected_hardlinks 2>/dev/null)" = "1" ]; then
    ok "2.6.3. Проверка fs.protected_hardlinks... "
else
    fail "2.6.3. Проверка fs.protected_hardlinks... "
fi

# 2.6.4. Проверка protected_fifos
if [ "$(sysctl -n fs.protected_fifos 2>/dev/null)" = "2" ]; then
    ok "2.6.4. Проверка fs.protected_fifos... "
else
    fail "2.6.4. Проверка fs.protected_fifos... "
fi

# 2.6.5. Проверка protected_regular
if [ "$(sysctl -n fs.protected_regular 2>/dev/null)" = "2" ]; then
    ok "2.6.5. Проверка fs.protected_regular... "
else
    fail "2.6.5. Проверка fs.protected_regular... "
fi

# 2.6.6. Проверка suid_dumpable
if [ "$(sysctl -n fs.suid_dumpable 2>/dev/null)" = "0" ]; then
    ok "2.6.6. Проверка fs.suid_dumpable... "
else
    fail "2.6.6. Проверка fs.suid_dumpable... "
fi

echo
echo "=== Проверка завершена ==="

# ДОРАБОТКА ВЫВОДОВ ПО ВЫЯВЛЕННЫМ ОШИБКАМ (расширенный вывод)

# Пример для /etc/shadow
if [ "$(stat -c %a /etc/shadow)" != "000" ] && [ "$(stat -c %a /etc/shadow)" != "600" ] && [ "$(stat -c %a /etc/shadow)" != "640" ]
then
  fail "2.3.1. Проверка прав на /etc/shadow (go-rwx)... "
  recommend "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
fi

# Детальный отчет по SUID/SGID и исполняемым из PATH
if [ "$all_ok" = false ]; then
  echo "[INFO] Список исполняемых файлов с правами на запись для группы/других:"
  for dir in $path_dirs; do
    if [ -d "$dir" ]; then
      find "$dir" -perm -002 -type f 2>/dev/null
    fi
  done
  recommend "использовать chmod go-w <файл> и проверить владельцев каталогов"
fi
if [ -n "$suid_with_wrong_owner_or_perms" ]; then
  echo "[INFO] SUID/SGID файлы с нарушениями (owner!=root или права содержат w):"
  echo "$suid_with_wrong_owner_or_perms"
  recommend "chown root <файл> и chmod go-w <файл>; при необходимости снять SUID/SGID"
fi
# Детальный отчет по домашним директориям и файлам пользователей
while IFS=: read -r username _ uid gid _ homedir shell; do
  if [ "$uid" -lt 1000 ] && [ "$username" != "root" ]; then continue; fi
  [ ! -d "$homedir" ] && continue
  checklog=""
  if [ "$(stat -c %a "$homedir" 2>/dev/null)" != "700" ]; then
    checklog+="[FAIL] $username: $homedir права $(stat -c %a "$homedir") (норма: 700)\n"
  fi
  filelist=(".bash_history" ".bash_profile" ".bashrc" ".profile" ".bash_logout" ".sh_history" ".history" ".rhosts")
  for fname in "${filelist[@]}"; do
    fpath="$homedir/$fname"
    [ -f "$fpath" ] || continue
    perms=$(stat -c %a "$fpath")
    if [ "${perms:2:1}" != "0" ] || [ "${perms:1:1}" != "0" ]; then
      checklog+="[FAIL] $username: $fpath права $perms (норма: --- для group/other)\n"
    fi
  done
  if [ -n "$checklog" ]; then
    echo -e "$checklog"
    recommend "chmod 700 '$homedir' && chmod 600 для файлов истории/настроек"
  fi
done < /etc/passwd
# Подробный отчет по sudoers
if [ -f /etc/sudoers ]; then
  echo "Пояснение: разрешение ALL/NOPASSWD для не-root пользователей повышает риск компрометации через ошибку в программе/правилах."
  recommend "разрешать только конкретные команды конкретным пользователям/группам и всегда требовать пароль"
  bad_entries=$(awk '/^[^#]/ && $1!~/root/ && $0~/ALL/ {print $0}' /etc/sudoers)
  if [ -n "$bad_entries" ]; then
    fail "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): Обнаружены подозрительные sudoers-строки (ALL для не-root):"
    echo "$bad_entries"
    echo "Метод устранения: убрать строки или сделать правило строго по пользователю и по списку команд, а не ALL"
  fi
  nopass_entries=$(awk '/^[^#]/ && $1!~/root/ && $0~/NOPASSWD/ {print $0}' /etc/sudoers)
  if [ -n "$nopass_entries" ]; then
    warn "2.2.2. Усиленная проверка /etc/sudoers (ищем строки с ALL, NOPASSWD не для root): Найдены строки с NOPASSWD (нет запроса пароля):"
    echo "$nopass_entries"
    echo "Риск: при эксплойте злоумышленник не будет запрошен пароль."
  fi
fi
# Для cron и init.d можно аналогично добавить поиск нарушителей при FAIL

# === РАСШИРЕННЫЕ (ДОПОЛНИТЕЛЬНЫЕ) ПРОВЕРКИ ПО ФСТЭК ===
echo

echo "[РАСШИРЕННО] 1. Анализ файлов в /etc/sudoers.d на наличие ALL/NOPASSWD не для root"
if [ -d /etc/sudoers.d ]; then
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    entries=$(awk '/^[^#]/ && $1!~/root/ && $0~/ALL/ {print FILENAME":"$0}' "$f")
    if [ -n "$entries" ]; then
      fail "[РАСШИРЕННО] 1. Анализ файлов в /etc/sudoers.d на наличие ALL/NOPASSWD не для root: $f содержит потенциально опасное разрешение:"
      echo "$entries"
      recommend "ограничить ALL/NOPASSWD конкретными пользователями и строго определённым списком команд"
    fi
    entries2=$(awk '/^[^#]/ && $1!~/root/ && $0~/NOPASSWD/ {print FILENAME\":\"$0}' "$f")
    if [ -n "$entries2" ]; then
      warn "[РАСШИРЕННО] 1. Анализ файлов в /etc/sudoers.d на наличие ALL/NOPASSWD не для root: $f содержит NOPASSWD для не-root"
      echo "$entries2"
      recommend "по возможности убрать NOPASSWD или ограничить конкретными безопасными командами"
    fi
  done
else
  echo "[INFO] /etc/sudoers.d не найден — доп. включённые правила sudo отсутствуют или не используются."
fi
echo

echo "[РАСШИРЕННО] 2. White-list аудит SUID/SGID-приложений"
# Типовой пример белого списка (можно настроить под свой дистрибутив)
white_list="/usr/bin/sudo /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/umount"
current_suid=$(find / -perm -4000 -type f 2>/dev/null)
for f in $current_suid; do
  echo "$white_list" | grep -Fxq "$f" || warn "[РАСШИРЕННО] 2. White-list аудит SUID/SGID-приложений: SUID $f не входит в рекомендуемый список. Проверьте является ли это исключением/угрозой."
done
recommend "снимать SUID/SGID-бит с лишних программ или удалять пакеты, если не используются (chmod u-s файл)"
echo

echo "[РАСШИРЕННО] 3. Проверка PAM: политика паролей, лимиты входов, блокировка brute-force"
echo "Пояснение: через PAM можно усилить политику сложных паролей и блокировать брутфорс."
if grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
  ok "[РАСШИРЕННО] 3. Проверка PAM: pam_pwquality — политика сложности паролей настроена."
else
  warn "[РАСШИРЕННО] 3. Проверка PAM: pam_pwquality не настроен в /etc/pam.d/common-password — пароли могут быть простыми!"
  recommend "добавить pam_pwquality (пример: password requisite pam_pwquality.so retry=3 minlen=12 difok=4)"
fi
if grep -q "pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
  ok "[РАСШИРЕННО] 3. Проверка PAM: pam_tally2/pam_faillock — лимит попыток настроен."
else
  warn "[РАСШИРЕННО] 3. Проверка PAM: pam_tally2 в /etc/pam.d/common-auth не найден. Возможен брутфорс без блокировки аккаунта."
  recommend "добавить pam_tally2.so или pam_faillock.so для ограничения числа попыток входа"
fi
echo

echo "[РАСШИРЕННО] 4. Проверка SELinux/AppArmor"
if sestatus 2>/dev/null | grep -q 'enforcing'; then
  ok "[РАСШИРЕННО] 4. Проверка SELinux/AppArmor: SELinux включен (enforcing mode)"
elif aa-status 2>/dev/null | grep -q 'enforce'; then
  ok "[РАСШИРЕННО] 4. Проверка SELinux/AppArmor: AppArmor включен (enforce mode)"
else
  warn "[РАСШИРЕННО] 4. Проверка SELinux/AppArmor: SELinux/AppArmor не включён или не установлен — система менее защищена от неверно работающих процессов"
  recommend "активировать и перевести в enforcing один из MAC-контролей (selinux-activate или aa-enforce)"
fi
echo

echo "[РАСШИРЕННО] 5. Проверка ulimits/limits.conf: нет ли разрешения на неограниченный доступ"
if grep -vE '^#|^$' /etc/security/limits.conf | grep -qi unlimited; then
  fail "[РАСШИРЕННО] 5. Проверка ulimits/limits.conf: найдены значения unlimited — любой пользователь может исчерпать ресурсы."
  recommend "задать конкретные soft/hard лимиты (nofile, nproc и др.) для всех пользователей или групп"
else
  ok "[РАСШИРЕННО] 5. Проверка ulimits/limits.conf: unlimited не обнаружены"
fi
echo

echo "[РАСШИРЕННО] 6. Расширенный аудит sshd_config (AllowUsers, PermitEmptyPasswords, X11Forwarding)"
sshd_file=/etc/ssh/sshd_config
if [ -f $sshd_file ]; then
  if grep -q "^PermitEmptyPasswords[ \t]*yes" $sshd_file; then
    fail "[РАСШИРЕННО] 6. Расширенный аудит sshd_config: разрешены пустые пароли (PermitEmptyPasswords yes)."
    recommend "установить PermitEmptyPasswords no и перезапустить sshd"
  fi
  if grep -q "^X11Forwarding[ \t]*yes" $sshd_file; then
    warn "[РАСШИРЕННО] 6. Расширенный аудит sshd_config: включён X11Forwarding — повышается поверхность атаки."
    recommend "отключить X11Forwarding (значение no) на сервере"
  fi
  if ! grep -Eq '^AllowUsers' $sshd_file; then
    echo '[INFO] AllowUsers не задан — вход возможен для всех валидных учёток.'
    recommend "прописать AllowUsers/AllowGroups для ограничения перечня допустимых подключений"
  fi
else
  warn "[РАСШИРЕННО] 6. Расширенный аудит sshd_config: файл sshd_config не найден — настройки неизвестны!"
fi
echo

echo "[РАСШИРЕННО] 7. Статус доп. важных сервисов (служб)"
services_to_check="telnet rsh ftp tftp rexec rlogin"
for s in $services_to_check; do
  if systemctl is-enabled $s 2>/dev/null | grep -q 'enabled'; then
    fail "[РАСШИРЕННО] 7. Статус доп. важных сервисов: обнаружен включённый небезопасный сервис $s."
    recommend "systemctl disable --now $s (или удалите пакет, если не требуется)"
  fi
done
echo '[INFO] Если нет FAIL выше — опасные устаревшие службы неактивны.'
echo
# END РАСШИРЕННЫХ ПРОВЕРОК

# Вывод подробной информации по SUID/SGID
suid_with_wrong_owner_or_perms=$(find / -perm -4000 -type f -exec stat -c "%U %A %n" {} \; 2>/dev/null | awk '$1 != "root" || substr($2, 7, 1) == "w" || substr($2, 8, 1) == "w" { print $0 }')
if [ -n "$suid_with_wrong_owner_or_perms" ]; then
    echo "[ПОДРОБНОСТИ SUID/SGID с проблемами]:"
    echo "$suid_with_wrong_owner_or_perms"
fi
# Подробная проверка shadow
shadow_stat=$(stat /etc/shadow 2>&1)
if [ "$(stat -c %a /etc/shadow)" != "000" ] && [ "$(stat -c %a /etc/shadow)" != "640" ]; then
    echo "[ПОДРОБНОСТИ] /etc/shadow права: $shadow_stat"
fi
# Подробный отчет для домашних директорий
while IFS=: read -r username _ uid gid _ homedir shell; do
    if [ "$uid" -lt 1000 ] && [ "$username" != "root" ]; then continue; fi
    [ ! -d "$homedir" ] && continue
    dirp=$(stat -c %a "$homedir")
    echo "$username: домашняя: $homedir права: $dirp"
    filelist=(".bash_history" ".bash_profile" ".bashrc" ".profile" ".bash_logout" ".sh_history" ".history" ".rhosts")
    for fname in "${filelist[@]}"; do
        fpath="$homedir/$fname"
        if [ -f "$fpath" ]; then
            fperm=$(stat -c %a "$fpath")
            echo " $fpath права: $fperm"
        fi
    done
done < /etc/passwd
# Подробная проверка sys файлов cron
cron_sys_files="/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
for file in $cron_sys_files; do
    if [ -e "$file" ] || [ -d "$file" ]; then
        perms=$(stat -c %a "$file")
        echo "$file права: $perms"
    fi
done
# Подробная проверка PATH
for dir in $(echo $PATH | tr ':' '\n'); do
    [ -d "$dir" ] || continue
    find "$dir" -perm -002 -type f -exec ls -l {} \; 2>/dev/null
done
# Подробная проверка sudoers
if [ -f /etc/sudoers ]; then
    awk '/^[^#]/ && $1!~/root/ && $0~/ALL/ {print "[ALL не для root] " $0}' /etc/sudoers
    awk '/^[^#]/ && $1!~/root/ && $0~/NOPASSWD/ {print "[NOPASSWD не для root] " $0}' /etc/sudoers
fi

# ---- [РАСШИРЕННЫЙ АУДИТ ПО ФСТЭК] ----
echo

echo '=== [Дополнительные проверки (расширенный аудит)] ==='

# 1. Анализ /etc/sudoers.d
if [ -d /etc/sudoers.d ]; then
  echo '> Проверка дополнительных include-файлов sudoers.d'
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    awk '/^[^#]/ && $1!~/root/ && $0~/ALL/ {print "[FAIL] В " FILENAME ": " $0; print "РЕКОМЕНДОВАНО: убрать ALL кроме root. Ограничить доступ конкретному пользователю/группе и командам!"}' "$f"
    awk '/^[^#]/ && $1!~/root/ && $0~/NOPASSWD/ {print "[WARN] В " FILENAME " (NOPASSWD не для root): " $0; print "РЕКОМЕНДОВАНО: по возможности NOPASSWD убрать либо строго ограничить список команд."}' "$f"
  done
fi

# 2. SELinux/AppArmor статус
if command -v getenforce >/dev/null 2>&1; then
  sel=$(getenforce)
  echo -n '> SELinux status: '
  echo "$sel"
  [ "$sel" = "Enforcing" ] || warn "[РАСШИРЕННО] 5. Проверка ulimits/limits.conf: нет ли разрешения на неограниченный доступ: SELinux не в режиме Enforcing. РЕКОМЕНДАЦИЯ: Включить SELinux enforcement для максимальной защиты."
else
  echo '> Проверка AppArmor'
  if command -v aa-status >/dev/null 2>&1; then
    aastat=$(aa-status | head -1)
    echo "AppArmor: $aastat"
    if ! aa-status | grep -q 'enforce'; then
      warn "[РАСШИРЕННО] 5. Проверка ulimits/limits.conf: нет ли разрешения на неограниченный доступ: AppArmor не в режиме enforce. РЕКОМЕНДАЦИЯ: Включить AppArmor."'
    fi
  else
    echo '[INFO] Не найден SELinux и AppArmor. В ОС нет мандатного контроля доступа.'
  fi
fi

# 3. Аудит сервисов (пример для telnet/ftp)
echo '> Статус запрещённых сервисов (telnet, ftp, rsh, talk и др.)'
for svc in telnet.socket telnetd vsftpd xinetd rsh-server talk-server tftp; do
  if systemctl list-units --type=service --type=socket | grep -iq $svc; then
    echo "[FAIL] Сервис $svc найден в системе. РЕКОМЕНДУЕТСЯ отключить: systemctl disable --now $svc"
  fi
done

# 4. PAM: аудит конфигов nullok, permit, deny и контроля входа
for pamfile in /etc/pam.d/*; do
  grep -Eq 'nullok|permit|deny|pam_shells|faillock|pam_tally' "$pamfile" && \
   warn "[РАСШИРЕННО] 4. Проверка SELinux/AppArmor: PAM ($pamfile): найдено использование nullok/permit/deny/shells/faillock/tally. Проверьте настройки на соответствие политике ФСТЭК!"
done

echo '> Аудит sshd_config (важные параметры)'
[ -f /etc/ssh/sshd_config ] && {
  grep -E '^X11Forwarding\s+yes' /etc/ssh/sshd_config && warn "[РАСШИРЕННО] 6. Расширенный аудит sshd_config (AllowUsers, PermitEmptyPasswords, X11Forwarding): X11Forwarding разрешён. РЕКОМЕНДУЕТСЯ запретить."
  grep -E '^PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config && warn "[РАСШИРЕННО] 6. Расширенный аудит sshd_config (AllowUsers, PermitEmptyPasswords, X11Forwarding): PermitEmptyPasswords разрешён. РЕКОМЕНДУЕТСЯ запретить."
  awk '/^AllowUsers/ {print "AllowUsers: " $0 " (разрешённые юзеры, иные блокируются)"}' /etc/ssh/sshd_config
}

echo '> Проверка security limits (лимиты ресурсов)'
grep -E '^[^#].*(nofile|nproc|fsize|data|core|rss|memlock|stack)' /etc/security/limits.conf | awk '{print "limits.conf: ", $0}'
# find soft/hard по nproc для всех, кроме root
grep -E '^[^#].*nproc' /etc/security/limits.conf |awk '$1!~"root" {print "nproc для не-root: ", $0}'

echo "[INFO] Если FAIL или WARN: ознакомьтесь с рекомендациями ФСТЭК, при необходимости настройте исправление вручную (chmod, chown, sysctl, редактирование конфигов и перезапуск сервисов)."
# ---- [КОНЕЦ РАСШИРЕННОГО АУДИТА] ---