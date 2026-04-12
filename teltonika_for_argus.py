import secrets
import time
import string
import paramiko
import socket
import getpass
import os
import sys
import platform
import subprocess
import ctypes
import requests
from scp import SCPClient
import tarfile
import re

# ============================================================
#  ЦВЕТА
# ============================================================
class C:
    OK    = "\033[92m"
    WARN  = "\033[93m"
    ERR   = "\033[91m"
    INFO  = "\033[96m"
    DEBUG = "\033[2;90m"
    RESET = "\033[0m"

def ok(msg):   print(f"{C.OK}[+]{C.RESET} {msg}")
def warn(msg): print(f"{C.WARN}[!]{C.RESET} {msg}")
def err(msg):  print(f"{C.ERR}[-]{C.RESET} {msg}")
def info(msg): print(f"{C.INFO}[*]{C.RESET} {msg}")
def debug(msg): print(f"{C.DEBUG}[#] {msg} {C.RESET} ")

# ============================================================
#  ФАЙЛЫ
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIRMWARE = os.path.join(BASE_DIR, "update.bin")
BACKUP   = os.path.join(BASE_DIR, "backup.tar.gz")

def check_files():
    missing = []
    if not os.path.exists(FIRMWARE):
        missing.append(FIRMWARE)
    if not os.path.exists(BACKUP):
        missing.append(BACKUP)
    if missing:
        for f in missing:
            err(f"Файл не найден: {f}")
        sys.exit(1)
    ok(f"Прошивка: {FIRMWARE}  ({os.path.getsize(FIRMWARE) // 2048} MB)")
    ok(f"Бэкап:    {BACKUP}  ({os.path.getsize(BACKUP) // 2048} MB)")

# ============================================================
#  ВХОДНЫЕ ДАННЫЕ
# ============================================================
DEFAULT_IP = "192.168.1.1"

def get_inputs():
    print()
    info("===+++ ПАРАМЕТРЫ +++===")




    router_ip = DEFAULT_IP
    ok(f"Используем IP: {router_ip} (захардкожено)")
    lan_ip   = input(" Новый LAN IP роутера с маской (например 172.26.15.161/29): ").strip()
    wg_ip    = input(" Новый WG IP интерфейса (например 172.26.10.133): ").strip()
    password = getpass.getpass(" Root password: ")
    print()
    debug(f"Введённые параметры:\n"
          f"  Router IP : {router_ip}\n"
          f"  LAN IP    : {lan_ip}\n"
          f"  WG IP     : {wg_ip}\n"
          f"  Password  : {password}\n")
    return router_ip, lan_ip, wg_ip, password




# ============================================================
#  СЕТЕВЫЕ УТИЛИТЫ (добавление IP на винде/линуксе)
# ============================================================
def is_admin():
    """Проверяет, запущен ли скрипт с правами администратора (Windows)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ensure_admin_windows():
    """Перезапускает скрипт с правами администратора, если нужно"""
    if platform.system() != "Windows":
        return
    if not is_admin():
        warn("Требуются права администратора для добавления IP-адресов. Перезапускаю...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def get_interface():
    """Возвращает имя активного сетевого интерфейса"""
    system = platform.system()
    if system == "Windows":
        # Способ 1: netsh (надёжнее wmic)
        try:
            out = subprocess.run(
                "netsh interface ipv4 show interfaces",
                shell=True, capture_output=True, text=True
            )
            debug(f"netsh interfaces output:\n{out.stdout.strip()}")
            for line in out.stdout.splitlines():
                # Строки вида: "15  connected  ... Ethernet"
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1].lower() == "connected":
                    iface = " ".join(parts[3:])
                    debug(f"Найден интерфейс (netsh): {iface}")
                    return iface
        except Exception as e:
            debug(f"netsh failed: {e}")

        # Способ 2: wmic
        try:
            out = subprocess.run(
                'wmic nic where "NetEnabled=True" get NetConnectionID',
                shell=True, capture_output=True, text=True
            )
            debug(f"wmic output:\n{out.stdout.strip()}")
            for line in out.stdout.splitlines()[1:]:
                iface = line.strip()
                if iface:
                    debug(f"Найден интерфейс (wmic): {iface}")
                    return iface
        except Exception as e:
            debug(f"wmic failed: {e}")

        # Способ 3: спрашиваем пользователя
        warn("Не удалось автоопределить интерфейс")
        iface = input("  Введи имя интерфейса вручную (например Ethernet, Wi-Fi): ").strip()
        return iface if iface else "Ethernet"
    else:
        # Linux
        try:
            out = subprocess.run("ip route | grep default | awk '{print $5}'", shell=True, capture_output=True, text=True)
            iface = out.stdout.strip()
            if iface:
                return iface
        except:
            pass
        return "eth0"

def get_assistant_ip(base_ip, offset=1):
    """Добавляет offset к последнему октету IP-адреса"""
    parts = base_ip.split(".")
    if len(parts) != 4:
        return None
    try:
        last = int(parts[3])
        new_last = last + offset
        if new_last > 254:
            warn(f"Не могу создать IP: {base_ip} + {offset} > 254")
            return None
        parts[3] = str(new_last)
        return ".".join(parts)
    except ValueError:
        return None

PREFIX_TO_MASK = {
    24: "255.255.255.0",
    25: "255.255.255.128",
    28: "255.255.255.240",
    29: "255.255.255.248",
    30: "255.255.255.252",
}

def ip_exists_with_prefix(ip, prefix, interface):
    """Проверяет, назначен ли IP с правильной маской. Если IP есть но маска не та — удаляет."""
    system = platform.system()
    mask = PREFIX_TO_MASK.get(prefix, "255.255.255.0")

    if system == "Windows":
        out = subprocess.run(
            f'netsh interface ipv4 show addresses "{interface}"',
            shell=True, capture_output=True, text=True
        ).stdout
        if ip not in out:
            return False  # IP нет вообще — надо добавить
        # IP есть — проверяем маску
        if mask in out:
            return True   # IP есть с правильной маской
        # IP есть но с другой маской — удаляем
        debug(f"{ip} есть но с неправильной маской, удаляю...")
        subprocess.run(
            f'netsh interface ipv4 delete address "{interface}" {ip}',
            shell=True, capture_output=True
        )
        return False
    else:
        out = subprocess.run(
            f"ip addr show dev {interface}",
            shell=True, capture_output=True, text=True
        ).stdout
        if f"{ip}/{prefix}" in out:
            return True   # IP есть с правильным префиксом
        if ip in out:
            # IP есть но с другим префиксом — удаляем
            debug(f"{ip} есть но с неправильным префиксом, удаляю...")
            subprocess.run(f"sudo ip addr del {ip} dev {interface}", shell=True, capture_output=True)
        return False

def add_ip_address(ip, interface=None, prefix=24):
    """Добавляет IP-адрес с указанным префиксом на интерфейс"""
    if not interface:
        interface = get_interface()
    system = platform.system()

    if ip_exists_with_prefix(ip, prefix, interface):
        info(f"  {ip}/{prefix} уже назначен на {interface}, пропускаю")
        return True

    debug(f"Добавляю {ip}/{prefix} на {interface}")

    if system == "Windows":
        mask = PREFIX_TO_MASK.get(prefix, "255.255.255.0")
        cmd = f'netsh interface ipv4 add address "{interface}" {ip} {mask}'
    else:
        cmd = f"sudo ip addr add {ip}/{prefix} dev {interface}"

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    else:
        warn(f"  Ошибка добавления {ip}/{prefix}: {result.stderr.strip() or result.stdout.strip()}")
        return False

def setup_assistant_ips(router_ip, backup_ip, lan_ip):
    """Добавляет вспомогательные IP-адреса для всех этапов работы"""
    info("Настройка дополнительных IP-адресов на локальном интерфейсе...")
    ensure_admin_windows()

    interface = get_interface()
    info(f"Интерфейс: {interface}")

    # Для recovery (доступ к 192.168.1.1) — нужен адрес в той же подсети
    recovery_subnet = router_ip.rsplit(".", 1)[0]  # 192.168.1
    assistant_for_recovery = f"{recovery_subnet}.10"

    # Для бэкапного IP — +1 к последнему октету
    assistant_for_backup = get_assistant_ip(backup_ip, 1)
    if not assistant_for_backup:
        assistant_for_backup = f"{backup_ip.rsplit('.', 1)[0]}.10"

    # Для финального LAN IP — +3 к последнему октету
    assistant_for_lan = get_assistant_ip(lan_ip, 3)
    if not assistant_for_lan:
        assistant_for_lan = f"{lan_ip.rsplit('.', 1)[0]}.10"

    # prefix=24 для recovery (192.168.1.x), prefix=29 для подсетей роутеров
    ips_to_add = [
        (assistant_for_recovery, "recovery (192.168.1.x)", 24),
        (assistant_for_backup,   f"backup ({backup_ip})",  29),
        (assistant_for_lan,      f"lan ({lan_ip})",        29),
    ]

    all_ok = True
    for ip, label, prefix in ips_to_add:
        info(f"Добавляю {ip}/{prefix}  [{label}]")
        if not add_ip_address(ip, interface, prefix):
            warn(f"  Не удалось добавить {ip}/{prefix} — продолжаю, но возможны проблемы с доступом")
            all_ok = False
        else:
            ok(f"  {ip}/{prefix} готов")

    if all_ok:
        ok("Все вспомогательные адреса готовы")
    else:
        warn("Часть адресов не добавлена — проверь права и интерфейс")



# ============================================================
#  1. ЗАГРУЗКА ПРОШИВКИ (Recovery mode WebUI)
# ============================================================



def remove_ip_address(ip, interface):
    """Удаляет IP-адрес с интерфейса"""
    system = platform.system()
    if system == "Windows":
        result = subprocess.run(
            f'netsh interface ipv4 delete address "{interface}" {ip}',
            shell=True, capture_output=True, text=True
        )
    else:
        result = subprocess.run(
            f"sudo ip addr del {ip} dev {interface}",
            shell=True, capture_output=True, text=True
        )
    if result.returncode == 0:
        ok(f"  {ip} удалён")
    else:
        warn(f"  Не удалось удалить {ip}: {result.stderr.strip() or result.stdout.strip()}")

def cleanup_assistant_ips(router_ip, backup_ip, lan_ip):
    """Удаляет вспомогательные IP добавленные в setup_assistant_ips"""
    info("Удаление вспомогательных IP-адресов с локального интерфейса...")
    interface = get_interface()

    recovery_subnet = router_ip.rsplit(".", 1)[0]
    assistant_for_recovery = f"{recovery_subnet}.10"
    assistant_for_backup = get_assistant_ip(backup_ip, 1) or f"{backup_ip.rsplit('.', 1)[0]}.10"
    assistant_for_lan    = get_assistant_ip(lan_ip, 3)    or f"{lan_ip.rsplit('.', 1)[0]}.10"

    for ip in [assistant_for_recovery, assistant_for_backup, assistant_for_lan]:
        info(f"Удаляю {ip}...")
        remove_ip_address(ip, interface)

    ok("Вспомогательные адреса удалены")


def upload_firmware(ip):
    info("===+++ НАЧАЛО ОБНОВЛЕНИЯ +++===")
    url = f"http://{ip}/"
    info(f"Проверяю доступность recovery mode на {url} ...")

    # Ждём, пока веб-сервер поднимется (до 30 сек)
    max_attempts = 6
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.get(url, timeout=5)
            debug(f"Вернул {resp.status_code}")
            # В recovery обычно возвращается страница с формой загрузки прошивки
            if resp.status_code == 200:
                ok("Recovery mode доступен")
                break
            else:
                warn(f"Странный статус {resp.status_code}, пробую ещё...")
        except requests.exceptions.RequestException as e:
            warn(f"Попытка {attempt}/{max_attempts}: {e}")
            time.sleep(5)
    else:
        err("Роутер не отвечает по HTTP. Убедись, что он в recovery mode (держи RESET при включении питания)")
        sys.exit(1)

    info(f"Загрузка прошивки → {url}")
    info("Это займёт ~1-2 минуты, не прерывай...")

    try:
        with open(FIRMWARE, "rb") as f:
            resp = requests.post(
                url,
                files={"firmware": ("update.bin", f, "application/octet-stream")},
                timeout=120,
            )
        if resp.status_code == 200:
            ok(f"Прошивка принята (HTTP {resp.status_code})")
        else:
            err(f"Ошибка загрузки прошивки: HTTP {resp.status_code}")
            err(f"Ответ сервера: {resp.text[:200]}")
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        # Recovery mode часто рвёт соединение сразу после успешного приёма файла
        ok("Прошивка принята — роутер начал прошивку (соединение оборвано, это нормально)")

    except requests.exceptions.Timeout:
        warn("Таймаут при загрузке — роутер мог уже принять файл и уйти в прошивку, проверь индикацию")

    except Exception as e:
        err(f"Неожиданная ошибка при загрузке прошивки: {e}")
        sys.exit(1)

    info("Жду, пока роутер прошьётся и перезагрузится (200 сек)...")
    time.sleep(200)




# ============================================================
#  2. ОЖИДАНИЕ SSH
# ============================================================
def wait_ssh(ip, timeout=500):
    info(f"Ожидаю SSH на {ip} (до {timeout} сек)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.create_connection((ip, 22), timeout=3)
            s.close()
            ok("SSH доступен")
            return True
        except Exception:
            time.sleep(5)
    err(f"SSH не поднялся за {timeout} сек")
    return False

# ============================================================
#  SSH
# ============================================================
def ssh_connect(ip, password, retries=6, delay=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(1, retries + 1):
        try:
            client.connect(ip, username="root", password=password, timeout=10)
            ok("SSH подключён")
            return client
        except Exception as e:
            warn(f"SSH попытка {attempt}/{retries}: {e}")
            time.sleep(delay)
    err("Не удалось подключиться по SSH")
    sys.exit(1)

def run(client, cmd, log=False):
    _, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode()
    er  = stderr.read().decode()
    if log:
        if out.strip(): print(out.strip())
        if er.strip():  warn(er.strip())
    return out, er

# ============================================================
#  3. ЗАГРУЗКА И ВОССТАНОВЛЕНИЕ БЭКАПА
# ============================================================
def upload_backup(client):
    info("Загрузка бэкапа на роутер...")
    scp = SCPClient(client.get_transport())
    scp.put(BACKUP, "/tmp/backup.tar.gz")
    scp.close()
    ok("Бэкап загружен → /tmp/backup.tar.gz")



# Получение LAN IP и маски из бэкапа
def get_backup_lan_info(backup_path):
    """Возвращает (ip, prefix) из секции lan бэкапа, например ('172.26.15.153', '29')"""
    try:
        with tarfile.open(backup_path, "r:gz") as tar:
            f = tar.extractfile("etc/config/network")
            if f is None:
                raise Exception("Файл etc/config/network не найден в архиве")
            raw = f.read().decode()
    except Exception as e:
        warn(f"Не удалось прочитать конфиг сети из бэкапа: {e}")
        return "192.168.1.1", "24"

    in_lan = False
    ip     = None
    prefix = None

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("config interface") and "'lan'" in line:
            in_lan = True
            continue
        if in_lan and line.startswith("config "):
            break  # вышли из блока lan
        if in_lan and "option ipaddr" in line:
            val = line.split("'")[1] if "'" in line else line.split()[-1]
            if "/" in val:
                ip, prefix = val.split("/", 1)
            else:
                ip = val
        if in_lan and "option netmask" in line:
            # netmask вида 255.255.255.248 → конвертим в prefix
            val = line.split("'")[1] if "'" in line else line.split()[-1]
            try:
                mask_int = sum(bin(int(x)).count("1") for x in val.split("."))
                prefix = str(mask_int)
            except Exception:
                pass

    if ip:
        prefix = prefix or "24"
        debug(f"Бэкап LAN: {ip}/{prefix}")
        return ip, prefix

    warn("LAN IP не найден в бэкапе, использую 192.168.1.1/24")
    return "192.168.1.1", "24"


def get_backup_lan_ip(backup_path):
    """Обратная совместимость — возвращает только IP"""
    ip, _ = get_backup_lan_info(backup_path)
    return ip

################################
#    Восстановление бэкапа
################################

def restore_backup(client):

    info("Восстановление бэкапа...")
    backup_ip = get_backup_lan_ip(BACKUP)

    if not backup_ip:
        err("Не удалось извлечь LAN IP из бэкапа")
        sys.exit(1)
    warn(f"После восстановления роутер будет доступен по IP: {backup_ip}")

    # Пароль из бэкапа нужен ДО разрыва соединения
    backup_password = getpass.getpass("Пароль из бэкапа: ")

    info("Отправляю sysupgrade -r и принудительно рву SSH-сессию...")

    transport = client.get_transport()
    #Отработка ошибок двойного вызва события
    if transport is None:
        err("Не удалось получить транспорт SSH")
        sys.exit(1)

    # Создаём канал, выполняем команду и сразу закрываем, обнова должна встать
    channel = transport.open_session()
    channel.exec_command("sysupgrade -r /tmp/backup.tar.gz")
    channel.close()
    transport.close()
    client.close()

    time.sleep(2)

    warn(f"SSH разорван ")

    #Ожидание нового коннекта

    if not wait_ssh(backup_ip, timeout=500):
        err("Роутер не поднялся после восстановления")
        sys.exit(1)


    #пересоздание ssh коннекта

    new_client = ssh_connect(backup_ip, backup_password)
    ok("Переподключились к роутеру после восстановления")
    return new_client, backup_ip, backup_password


# ============================================================
#  4. НАСТРОЙКА LAN
# ============================================================



def generate_password(length=14):
    """Генерирует пароль: строчные буквы + цифры + спецсимволы"""
    chars = string.ascii_lowercase + string.digits + "^$[]#?!@&*"
    # Гарантируем хотя бы один символ каждого типа
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("^$[]#?!@&*"),
    ]
    pwd += [secrets.choice(chars) for _ in range(length - len(pwd))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def change_router_password(client, new_password):
    """Меняет пароль пользователю admin (и остальным активным, если нужно)"""
    info("Смена пароля для admin...")

    # Принудительно меняем пароль для admin
    cmd_admin = f"echo 'admin:{new_password}' | chpasswd"
    _, er = run(client, cmd_admin)
    if er.strip() and "password" not in er.lower():
        warn(f"  admin: возможная ошибка — {er.strip()}")
    else:
        ok(f"  admin: пароль изменён")

    # Дополнительно меняем пароли остальным активным пользователям (опционально)
    out, _ = run(client, "cat /etc/passwd")
    users = []
    for line in out.strip().splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username = parts[0]
        shell = parts[6].strip()
        if shell in ("/bin/false", "/sbin/nologin", "/bin/nologin", ""):
            continue
        if username == "admin":
            continue  # уже обработали
        users.append(username)

    if users:
        debug(f"Найдены другие активные пользователи: {users}")
        for user in users:
            cmd = f"echo '{user}:{new_password}' | chpasswd"
            _, er = run(client, cmd)
            if er.strip() and "password" not in er.lower():
                warn(f"  {user}: возможная ошибка — {er.strip()}")
            else:
                ok(f"  {user}: пароль изменён")


def configure_lan(client, lan_ip):
    info(f"Выставляю LAN IP: {lan_ip}")
    run(client, f"uci set network.lan.ipaddr='{lan_ip}' && uci commit network")
    ok("LAN IP сохранён")



# ============================================================
#  5. WIREGUARD — генерация ключей и вывод паблика
# ============================================================
def ensure_wg_tools(client):
    out, _ = run(client, "which wg")
    if not out.strip():
        info("wg не найден — устанавливаю wireguard-tools...")
        run(client, "opkg update && opkg install wireguard-tools", log=True)

def generate_wg_keys(client):
    info("Генерация WireGuard ключей на роутере...")
    ensure_wg_tools(client)
    out, _ = run(client, 'priv=$(wg genkey); pub=$(echo $priv | wg pubkey); echo "$priv SPLIT $pub"')
    parts = out.strip().split("SPLIT")
    if len(parts) != 2:
        err("Не удалось получить WG ключи")
        sys.exit(1)
    priv, pub = parts[0].strip(), parts[1].strip()
    ok("Ключи сгенерированы")
    return priv, pub

def get_peer_params():
    """Запрашиваем данные пира ПОСЛЕ того как показали паблик роутера"""
    print()
    peer_pub = input("  Peer public key: ").strip()
    debug(f"Используется peer public key: {peer_pub}")
    psk      = input("  Preshared key:   ").strip()
    print()
    return peer_pub, psk

def detect_wg_section(client):
    """
    Парсит вывод 'uci show network | grep wireguard' и возвращает:
      section   - "network.vpn_tn"   (UCI-путь до интерфейса)
      peer_type - "wireguard_vpn_tn" (тип секции пиров)
      peer_name - "peer_vpn"         (имя существующей секции пира, или None)

    Примеры строк из uci show:
      network.vpn_tn.proto='wireguard'   -> section
      network.peer_vpn=wireguard_vpn_tn  -> peer_name / peer_type
    """
    out, _ = run(client, "uci show network | grep wireguard")

    section   = None
    peer_type = None
    peer_name = None

    for line in out.strip().splitlines():
        line = line.strip()

        # network.vpn_tn.proto='wireguard'
        if ".proto='wireguard'" in line or ".proto=wireguard" in line:
            parts = line.split(".")
            if len(parts) >= 2:
                section = f"{parts[0]}.{parts[1]}"   # network.vpn_tn

        # network.peer_vpn=wireguard_vpn_tn
        elif "=wireguard_" in line:
            left, right = line.split("=", 1)         # network.peer_vpn / wireguard_vpn_tn
            parts = left.split(".")
            if len(parts) >= 2:
                peer_name = parts[1]                 # peer_vpn
                peer_type = right                    # wireguard_vpn_tn

    # Если пир не нашли — строим peer_type из имени интерфейса
    if section and not peer_type:
        iface_name = section.split(".")[-1]
        peer_type  = f"wireguard_{iface_name}"

    return section, peer_type, peer_name


def calc_network(ip, prefix):
    """Вычисляет сетевой адрес: ip - 1 от последнего октета + маска"""
    parts = ip.split(".")
    last = int(parts[3]) - 1
    parts[3] = str(last)
    net = f"{'.'.join(parts)}/{prefix}"
    debug(f"Сетевой адрес: {net}")
    return net


def configure_wg(client, wg_ip, lan_ip, lan_prefix, backup_ip, backup_prefix, password):
    """
    Правит существующий WG конфиг из бэкапа:
      - генерит новый приватный ключ, выводит паблик в терминал
      - обновляет addresses интерфейса (wg_ip/32)
      - в allowed_ips пира заменяет старую сеть (backup_ip/backup_prefix)
        на новую (lan_ip/lan_prefix)
      - обновляет peer_pub и psk пира
    """
    info("Настройка WireGuard UCI...")

    section, peer_type, peer_name = detect_wg_section(client)

    if not section:
        err("WireGuard секция не найдена в конфиге — проверь бэкап")
        sys.exit(1)

    info(f"Секция интерфейса : {section}")
    if peer_name:
        info(f"Секция пира       : network.{peer_name}")

    # 1. Генерим новый приватный ключ, паблик выводим в терминал
    priv, pub = generate_wg_keys(client)
    print(f"\n{C.OK}╔══════════════════════════════════════════════╗")
    print(f"  PUBLIC KEY роутера (добавь на пир-сервере):  ")
    print(f"  {pub}")
    print(f"╚══════════════════════════════════════════════╝{C.RESET}\n")

    # Вводим данные ответного пира
    peer_pub, psk = get_peer_params()

    # 2-3. Приватный ключ + адрес интерфейса
    # Teltonika иногда рвёт SSH при записи длинной строки приватного ключа.
    # UCI при этом НЕ применяется — после reconnect повторяем запись.
    def write_wg_keys(c):
        run(c, f"uci set {section}.private_key='{priv}'")
        run(c, f"uci set {section}.public_key='{pub}'")
        # delete удаляет весь список addresses, потом добавляем один новый
        run(c, f"uci -q delete {section}.addresses; true")
        run(c, f"uci add_list {section}.addresses='{wg_ip}/32'")

    try:
        write_wg_keys(client)
        ok(f"Приватный ключ и адрес интерфейса записаны ({wg_ip}/32)")
    except Exception as e:
        warn(f"SSH разорван при записи ключей ({e}), переподключаюсь на {lan_ip}...")
        if not wait_ssh(lan_ip, timeout=120):
            err(f"Роутер не поднялся на {lan_ip} — проверь вручную")
            sys.exit(1)
        client = ssh_connect(lan_ip, password)
        ok("Переподключились, повторяю запись ключей...")
        write_wg_keys(client)
        ok(f"Приватный ключ и адрес интерфейса записаны ({wg_ip}/32)")

    # 4. Обновляем allowed_ips пира — заменяем старую сеть на новую
    if peer_name:
        peer_path = f"network.{peer_name}"

        # backup_ip = LAN IP роутера из бэкапа (напр. 153), -1 даёт сетевой адрес (152)
        # lan_ip    = новый LAN IP роутера (напр. 161),    -1 даёт сетевой адрес (160)
        old_net = calc_network(backup_ip, backup_prefix)   # 172.26.15.153 → 172.26.15.152/29
        new_net = calc_network(lan_ip, lan_prefix)         # 172.26.15.161 → 172.26.15.160/29

        # Читаем текущий список allowed_ips
        out, _ = run(client, f"uci get {peer_path}.allowed_ips 2>/dev/null || true")
        current = out.strip().split()
        debug(f"allowed_ips до правки: {current}")

        if old_net not in current:
            warn(f"Старая сеть {old_net} не найдена в allowed_ips — добавляю новую без удаления старой")
            run(client, f"uci add_list {peer_path}.allowed_ips='{new_net}'")
        else:
            run(client, f"uci del_list {peer_path}.allowed_ips='{old_net}'")
            run(client, f"uci add_list {peer_path}.allowed_ips='{new_net}'")
            ok(f"allowed_ips: {old_net} → {new_net}")

        # 5. Обновляем ключи пира
        run(client, f"uci set {peer_path}.public_key='{peer_pub}'")
        run(client, f"uci set {peer_path}.preshared_key='{psk}'")
        ok("Ключи пира обновлены")
    else:
        warn("Пир не найден — allowed_ips и ключи пира не обновлены")

    run(client, "uci commit network")
    ok("WireGuard конфигурация обновлена")
    return client  # возвращаем клиент — мог пересоздаться при reconnect

def restart_network(client):
    info("Перезапуск сети...")
    run(client, "/etc/init.d/network restart")
    time.sleep(8)
    ok("Сеть перезапущена")

# ============================================================
#  7. ФИНАЛЬНЫЙ REBOOT
# ============================================================
def final_reboot(client):
    info("Финальная перезагрузка роутера...")
    try:
        run(client, "reboot")
    except Exception:
        pass
    client.close()
    ok("Reboot отправлен")

# ============================================================
#  8. ПРОВЕРКИ ПОСЛЕ REBOOT
# ============================================================
def post_check_ssh(ip, password):
    info("Проверка SSH после перезагрузки...")
    if not wait_ssh(ip, timeout=180):
        err("Роутер не поднялся по SSH после reboot")
        return None
    client = ssh_connect(ip, password)
    ok("Роутер доступен по SSH")
    return client

def check_wg_tunnel(client):
    info("Проверка WireGuard туннеля...")
    out, _ = run(client, "wg show")
    if not out.strip():
        warn("wg show пустой — туннель не поднят, проверь пира")
    else:
        ok("WireGuard туннель активен:")
        print(out.strip())

# ============================================================
#  MAIN
# ============================================================
def main():
    print(f"\n{C.INFO}{'='*52}")
    print("  Teltonika RUT200 — автообновление + настройка")
    print(f"{'='*52}{C.RESET}\n")

    # 0 Проверка файлов
    check_files()

    # 0.0 Ввод параметров
    router_ip, lan_ip, wg_ip, password = get_inputs()

    # 0.1 Читаем backup LAN IP и маску из бэкапа
    backup_ip_from_file, backup_prefix = get_backup_lan_info(BACKUP)
    debug(f"LAN из бэкапа: {backup_ip_from_file}/{backup_prefix}")

    # 0.2 Парсим lan_ip и маску из введённого (формат: 172.26.15.161/29)
    if "/" in lan_ip:
        lan_ip, lan_prefix = lan_ip.split("/", 1)
    else:
        lan_prefix = backup_prefix  # если маску не ввели — берём из бэкапа
        warn(f"Маска не указана, использую из бэкапа: /{lan_prefix}")

    debug(f"Новый LAN: {lan_ip}/{lan_prefix}")

    # 0.3 Добавляем вспомогательные IP на локальный интерфейс
    setup_assistant_ips(router_ip, backup_ip_from_file, lan_ip)

    # 1. Прошивка через Recovery WebUI
    upload_firmware(router_ip)

    # 2. Ждём SSH после прошивки
    if not wait_ssh(router_ip):
        err("Роутер не поднялся после прошивки — проверь вручную")
        sys.exit(1)

    client = ssh_connect(router_ip, password)

    # 3. Бэкап
    upload_backup(client)
    client, backup_ip, password = restore_backup(client)
    router_ip = backup_ip   # пока работаем на backup_ip
    # 4. LAN IP + переподключение на новый адрес
    configure_lan(client, lan_ip)

    # network restart рвёт SSH — запускаем через канал и сразу закрываем, не ждём ответа
    transport = client.get_transport()
    channel = transport.open_session()

    #отправляем команду на перезапуск сети, не дожидаясь её выполнения
    channel.exec_command("uci commit network && /etc/init.d/network restart")
    channel.close()
    transport.close()
    client.close()
    
    #переназначем ip для дальнейшей работы
    router_ip = lan_ip
    info(f"LAN IP применён, переподключаюсь на {lan_ip}...")
    time.sleep(5)
    if not wait_ssh(lan_ip, timeout=60):
        err(f"Роутер не поднялся на {lan_ip} после смены LAN IP")
        sys.exit(1)
    client = ssh_connect(lan_ip, password)
    ok(f"Переподключились на {lan_ip}")

    # 4.1 Генерим и меняем пароль роутера
    new_password = generate_password()
    change_router_password(client, new_password)
    print(f"\n{C.OK}╔══════════════════════════════════════════════╗")
    print(f"  Новый пароль роутера:                         ")
    print(f"  {new_password}")
    print(f"╚══════════════════════════════════════════════╝{C.RESET}\n")
    password = new_password  # обновляем для последующих reconnect

    # 5. WireGuard — правим существующий конфиг из бэкапа
    client = configure_wg(client, wg_ip, lan_ip, lan_prefix, backup_ip_from_file, backup_prefix, password)

    # 6. Перезапуск сети
    restart_network(client)

    # 7. Финальный reboot
    final_reboot(client)

    # 8. Проверка после reboot
    client2 = post_check_ssh(router_ip, password)
    if client2:
        check_wg_tunnel(client2)
        client2.close()

    # 9. Удаляем вспомогательные IP с локального интерфейса
    cleanup_assistant_ips(router_ip, backup_ip_from_file, lan_ip)

    print(f"\n{C.OK}{'='*52}")
    print("  Fucking update complite!")
    print(f"{'='*52}{C.RESET}\n")

if __name__ == "__main__":
    main()