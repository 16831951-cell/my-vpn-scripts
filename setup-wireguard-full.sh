#!/bin/bash

set -euo pipefail

# =============================================================================
# PRO-версия: WireGuard-сервер с QR-кодами, DNSCrypt и веб-интерфейсом
# Для Ubuntu 24.04 + TP-Link BE230
# Исправленная и улучшенная версия
# =============================================================================

if [[ $EUID -ne 0 ]]; then
   echo "❌ Ошибка: Этот скрипт должен быть запущен от root" >&2
   exit 1
fi

# ========================
# ПЕРЕМЕННЫЕ
# ========================
WG_CONFIG="/etc/wireguard/wg0.conf"
KEY_DIR="/etc/wireguard"
CLIENT_DIR="/root/wg-clients"
DNSCRYPT_CONF="/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
UI_DIR="/opt/wireguard-ui"
UI_PORT=8080

# Функция для логирования
log() {
    echo "📝 $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Функция проверки ошибок
check_error() {
    if [ $? -ne 0 ]; then
        echo "❌ Ошибка: $1"
        exit 1
    fi
}

# Определение сетевых параметров
log "Определение сетевых параметров..."
PUBLIC_IP=$(curl -s -4 https://api.ipify.org || curl -s -4 https://ifconfig.co || echo "ERROR")
if [[ -z "$PUBLIC_IP" || "$PUBLIC_IP" == "ERROR" ]]; then
    echo "❌ Не удалось определить публичный IPv4"
    read -p "Введите публичный IP сервера вручную: " PUBLIC_IP
fi

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
if [[ -z "$INTERFACE" ]]; then
    echo "❌ Не удалось определить сетевой интерфейс."
    ip link show
    read -p "Введите имя интерфейса (например, eth0): " INTERFACE
fi

echo "🌐 Используем интерфейс: $INTERFACE"
echo "🔑 Публичный IPv4: $PUBLIC_IP"

# Проверка интернет-соединения
if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
    echo "⚠️  Предупреждение: Проблемы с интернет-соединением"
fi

# Создаём директории
mkdir -p "$CLIENT_DIR"
mkdir -p "$(dirname "$DNSCRYPT_CONF")"

# ========================
# 1. ОБНОВЛЕНИЕ СИСТЕМЫ
# ========================
log "Обновление системы..."
apt update -y
apt upgrade -y

# ========================
# 2. УСТАНОВКА ОСНОВНЫХ ПАКЕТОВ
# ========================
log "Установка WireGuard и зависимостей..."
apt install -y wireguard iptables qrencode curl jq git resolvconf

# ========================
# 3. ГЕНЕРАЦИЯ КЛЮЧЕЙ СЕРВЕРА
# ========================
log "Генерация ключей сервера..."
mkdir -p "$KEY_DIR"
cd "$KEY_DIR"
umask 077
wg genkey | tee privatekey | wg pubkey > publickey

SERVER_PRIVATE_KEY=$(cat privatekey)
SERVER_PUBLIC_KEY=$(cat publickey)

# ========================
# 4. НАСТРОЙКА WIREGUARD (wg0.conf)
# ========================
log "Создание конфигурации сервера..."
cat <<EOF > "$WG_CONFIG"
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.8.0.1/24
SaveConfig = true
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
EOF

# ========================
# 5. ВКЛЮЧЕНИЕ IP FORWARDING
# ========================
log "Включение IP-форвардинга..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# ========================
# 6. ОТКРЫТИЕ ПОРТОВ В UFW
# ========================
log "Настройка UFW..."
if command -v ufw &> /dev/null; then
    ufw allow 51820/udp
    ufw allow "$UI_PORT/tcp"
    ufw allow ssh
    ufw --force enable
    echo "   Порты 51820/udp и $UI_PORT/tcp открыты."
else
    echo "⚠️  UFW не установлен, настройте фаервол вручную"
fi

# ========================
# 7. НАСТРОЙКА DNS И УСТАНОВКА DNSCRYPT-PROXY
# ========================
log "Настройка DNS системы..."
# Останавливаем systemd-resolved если он работает
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true

# Настраиваем resolv.conf
cat <<EOF > /etc/resolv.conf
nameserver 127.0.0.1
options edns0 trust-ad
EOF

chattr +i /etc/resolv.conf 2>/dev/null || true

log "Установка dnscrypt-proxy..."
apt install -y dnscrypt-proxy

# Резервная копия оригинального конфига
if [[ -f "$DNSCRYPT_CONF" ]]; then
    cp "$DNSCRYPT_CONF" "${DNSCRYPT_CONF}.backup"
fi

# Настройка dnscrypt-proxy
cat <<EOF > "$DNSCRYPT_CONF"
listen_addresses = ['127.0.0.1:53']
server_names = ['cloudflare', 'cloudflare-ipv6']
require_dnssec = true
require_nolog = true
require_nofilter = true
netprobe_timeout = 10
netprobe_address = '9.9.9.9:53'
logs_file = '/var/log/dnscrypt-proxy.log'
use_syslog = true

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''

[static]
  [static.'cloudflare']
  stamp = 'sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg81UlVI8m_J-TzLXpHP22g5Cyhrpl5g0GJ21mGAcF6aGFuZGxlLmNsb3VkZmxhcmUuZ29vZ2xlLmNvbQovZG5zLXF1ZXJ5'

  [static.'cloudflare-ipv6']
  stamp = 'sdns://AgcAAAAAAAAAEGlmcHY2LmNsb3VkZmxhcmWgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg81UlVI8m_J-TzLXpHP22g5Cyhrpl5g0GJ21mGAcF6aGFuZGxlLmNsb3VkZmxhcmUuZ29vZ2xlLmNvbQovZG5zLXF1ZXJ5'
EOF

systemctl enable dnscrypt-proxy
systemctl restart dnscrypt-proxy

# Проверка DNS
log "Проверка DNS..."
if dig google.com @127.0.0.1 +short &> /dev/null; then
    echo "✅ DNS работает корректно"
else
    echo "⚠️  Возможны проблемы с DNS"
fi

# ========================
# 8. УСТАНОВКА WIREGUARD-UI (wg-easy)
# ========================
log "Установка WireGuard-UI..."
mkdir -p "$UI_DIR"
cd "$UI_DIR"

# Получение последней версии wg-easy
log "Поиск последней версии wg-easy..."
LATEST_RELEASE=$(curl -s https://api.github.com/repos/WeeJeWel/wg-easy/releases/latest | jq -r '.tag_name // empty' | tr -d '"')

if [[ -z "$LATEST_RELEASE" || "$LATEST_RELEASE" == "null" ]]; then
    echo "⚠️  Не удалось получить версию, используем v4.1.5"
    LATEST_RELEASE="v4.1.5"
fi

echo "📦 Установка версии: $LATEST_RELEASE"

# Скачивание и распаковка
if curl -L "https://github.com/WeeJeWel/wg-easy/releases/download/${LATEST_RELEASE}/wg-easy-linux-amd64.tar.gz" -o wg-easy.tar.gz; then
    tar xzf wg-easy.tar.gz
    rm wg-easy.tar.gz
    chmod +x wg-easy
    echo "✅ wg-easy успешно установлен"
else
    echo "❌ Ошибка загрузки wg-easy"
    exit 1
fi

# Создание конфигурационного файла
cat <<EOF > "$UI_DIR/.env"
# WG Easy Environment
WG_HOST=$PUBLIC_IP
WG_PORT=51820
WG_MTU=1420
WG_PERSISTENT_KEEPALIVE=25
WG_DEFAULT_ADDRESS=10.8.0.x
WG_DEFAULT_DNS=127.0.0.1
WG_ALLOWED_IPS=0.0.0.0/0

# Web UI
UI_HOST=0.0.0.0
UI_PORT=$UI_PORT
UI_PASSWORD=admin
EOF

# Создание systemd-юнита
cat <<EOF > /etc/systemd/system/wg-easy.service
[Unit]
Description=WireGuard UI (wg-easy)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$UI_DIR
EnvironmentFile=$UI_DIR/.env
ExecStart=$UI_DIR/wg-easy
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wg-easy
systemctl start wg-easy

# ========================
# 9. УСТАНОВКА FAIL2BAN
# ========================
log "Установка fail2ban..."
apt install -y fail2ban

# Базовая конфигурация
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
EOF

systemctl enable fail2ban
systemctl start fail2ban

# ========================
# 10. ФУНКЦИЯ ДОБАВЛЕНИЯ КЛИЕНТА
# ========================
add_client() {
    local name="$1"
    if [[ -z "$name" ]]; then
        echo "❌ Укажите имя клиента: add_client имя_клиента"
        return 1
    fi

    # Проверка существования клиента
    if [[ -f "$CLIENT_DIR/${name}.conf" ]]; then
        echo "❌ Клиент '$name' уже существует!"
        return 1
    fi

    # Функция поиска свободного IP
    find_next_ip() {
        local used_ips=()
        if [[ -f "$WG_CONFIG" ]]; then
            while IFS= read -r line; do
                if [[ $line =~ ^AllowedIPs[[:space:]]*=[[:space:]]*([0-9.]+)/32 ]]; then
                    used_ips+=("${BASH_REMATCH[1]}")
                fi
            done < "$WG_CONFIG"
        fi

        for i in {2..254}; do
            local candidate_ip="10.8.0.$i"
            if [[ ! " ${used_ips[*]} " =~ " ${candidate_ip} " ]]; then
                echo "$candidate_ip"
                return 0
            fi
        done
        return 1
    }

    local next_ip=$(find_next_ip)
    if [[ -z "$next_ip" ]]; then
        echo "❌ Все IP-адреса заняты!"
        return 1
    fi

    echo "➕ Добавление клиента: $name (IP: $next_ip)"

    # Генерация ключей
    umask 077
    wg genkey | tee "$CLIENT_DIR/${name}_private.key" | wg pubkey > "$CLIENT_DIR/${name}_public.key"

    local client_private_key=$(cat "$CLIENT_DIR/${name}_private.key")
    local client_public_key=$(cat "$CLIENT_DIR/${name}_public.key")

    # Добавляем пира в конфиг сервера
    cat <<EOF >> "$WG_CONFIG"

[Peer]
PublicKey = $client_public_key
AllowedIPs = $next_ip/32
EOF

    # Генерируем конфиг клиента
    cat <<EOF > "$CLIENT_DIR/${name}.conf"
[Interface]
PrivateKey = $client_private_key
Address = $next_ip/24
DNS = 127.0.0.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Генерируем QR-код
    echo "📋 QR-код для клиента $name:"
    qrencode -t ansiutf8 < "$CLIENT_DIR/${name}.conf"
    echo
    
    # Обновляем конфигурацию WireGuard без полного перезапуска
    if systemctl is-active --quiet wg-quick@wg0; then
        wg addconf wg0 <(wg-quick strip wg0)
        echo "🔁 Конфигурация WireGuard обновлена"
    else
        systemctl restart wg-quick@wg0
    fi

    echo "✅ Клиент успешно добавлен!"
    echo "💾 Конфиг: $CLIENT_DIR/${name}.conf"
    echo "🌐 Веб-интерфейс: http://$PUBLIC_IP:$UI_PORT"
}

# ========================
# 11. ЗАПУСК И ПРОВЕРКА СЕРВИСОВ
# ========================
log "Запуск сервисов..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Небольшая пауза для инициализации
sleep 3

# Проверка статусов
log "Проверка статусов сервисов..."

echo "🔍 WireGuard:"
if systemctl is-active --quiet wg-quick@wg0; then
    echo "✅ Запущен"
    wg show
else
    echo "❌ Не запущен"
fi

echo "🔍 DNSCrypt-proxy:"
if systemctl is-active --quiet dnscrypt-proxy; then
    echo "✅ Запущен"
else
    echo "❌ Не запущен"
fi

echo "🔍 WG-Easy:"
if systemctl is-active --quiet wg-easy; then
    echo "✅ Запущен"
else
    echo "❌ Не запущен"
    journalctl -u wg-easy -n 10 --no-pager
fi

echo "🔍 Fail2ban:"
if systemctl is-active --quiet fail2ban; then
    echo "✅ Запущен"
else
    echo "❌ Не запущен"
fi

# ========================
# 12. СОХРАНЕНИЕ ФУНКЦИИ В .BASHRC
# ========================
BASHRC_FUNC_PATH="/root/.bashrc_wireguard"
log "Сохранение функции add_client..."

cat <<'EOF' > "$BASHRC_FUNC_PATH"
add_client() {
    local name="$1"
    if [[ -z "$name" ]]; then
        echo "❌ Укажите имя клиента: add_client имя_клиента"
        return 1
    fi

    local WG_CONFIG="/etc/wireguard/wg0.conf"
    local CLIENT_DIR="/root/wg-clients"
    local PUBLIC_IP=$(curl -s -4 https://api.ipify.org || echo "UNKNOWN")
    local used_ips=()

    if [[ -f "$WG_CONFIG" ]]; then
        while IFS= read -r line; do
            if [[ $line =~ ^AllowedIPs[[:space:]]*=[[:space:]]*([0-9.]+)/32 ]]; then
                used_ips+=("${BASH_REMATCH[1]}")
            fi
        done < "$WG_CONFIG"
    fi

    local next_ip=""
    for i in {2..254}; do
        local candidate_ip="10.8.0.$i"
        if [[ ! " ${used_ips[*]} " =~ " ${candidate_ip} " ]]; then
            next_ip="$candidate_ip"
            break
        fi
    done

    if [[ -z "$next_ip" ]]; then
        echo "❌ Все IP-адреса заняты!"
        return 1
    fi

    echo "➕ Добавление клиента: $name (IP: $next_ip)"

    umask 077
    wg genkey | tee "$CLIENT_DIR/${name}_private.key" | wg pubkey > "$CLIENT_DIR/${name}_public.key"

    local client_private_key=$(cat "$CLIENT_DIR/${name}_private.key")
    local client_public_key=$(cat "$CLIENT_DIR/${name}_public.key")
    local SERVER_PUBLIC_KEY=$(cat /etc/wireguard/publickey)

    cat <<EOF_INNER >> "$WG_CONFIG"

[Peer]
PublicKey = $client_public_key
AllowedIPs = $next_ip/32
EOF_INNER

    cat <<EOF_INNER > "$CLIENT_DIR/${name}.conf"
[Interface]
PrivateKey = $client_private_key
Address = $next_ip/24
DNS = 127.0.0.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF_INNER

    qrencode -t ansiutf8 < "$CLIENT_DIR/${name}.conf"
    echo
    echo "💾 Конфиг сохранён: $CLIENT_DIR/${name}.conf"
    echo "🖼 QR-код выше — сканируй его в приложении WireGuard!"
    
    if systemctl is-active --quiet wg-quick@wg0; then
        wg addconf wg0 <(wg-quick strip wg0)
        echo "🔁 WireGuard обновлён"
    fi
}
EOF

# Добавляем загрузку функции в .bashrc если её там нет
if ! grep -q "bashrc_wireguard" /root/.bashrc; then
    echo "source $BASHRC_FUNC_PATH" >> /root/.bashrc
fi

source "$BASHRC_FUNC_PATH"

# ========================
# 13. ФИНАЛЬНОЕ СООБЩЕНИЕ
# ========================
echo
echo "🎉 🎉 🎉 УСПЕШНО! ВСЁ НАСТРОЕНО! 🎉 🎉 🎉"
echo
echo "🔥 ОСНОВНЫЕ ССЫЛКИ:"
echo "   • Веб-интерфейс: http://$PUBLIC_IP:$UI_PORT"
echo "     (логин: admin, пароль: admin)"
echo "   • WireGuard-сервер: $PUBLIC_IP:51820"
echo "   • DNS: 127.0.0.1 (через DNSCrypt — шифрованный и безопасный)"
echo
echo "🛠 КОМАНДЫ УПРАВЛЕНИЯ:"
echo "   systemctl status wg-quick@wg0    # Статус WireGuard"
echo "   systemctl status wg-easy         # Статус веб-интерфейса"
echo "   systemctl status dnscrypt-proxy  # Статус DNS"
echo "   wg show                          # Подключенные клиенты"
echo
echo "👥 ДОБАВИТЬ КЛИЕНТА:"
echo "   add_client имя_клиента"
echo "   Пример: add_client tplink_be230"
echo
echo "📥 СКАЧАТЬ КОНФИГ:"
echo "   scp root@$PUBLIC_IP:/root/wg-clients/tplink_be230.conf ./"
echo
echo "🛡 БЕЗОПАСНОСТЬ:"
echo "   • UFW активен (порты 51820/udp, $UI_PORT/tcp, SSH)"
echo "   • Fail2ban защищает SSH"
echo "   • DNSCrypt шифрует DNS-запросы"
echo "   • Все подключения через TLS/HTTPS"
echo
echo "💡 ПОДКЛЮЧЕНИЕ TP-Link BE230:"
echo "   1. Открой веб-интерфейс роутера: http://192.168.1.1"
echo "   2. Перейди: Advanced → VPN → WireGuard Client"
echo "   3. Нажми Add → Вставь содержимое файла: /root/wg-clients/tplink_be230.conf"
echo "   4. Включай клиент → Проверь IP на https://whatismyipaddress.com"
echo
echo "🔧 ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ:"
echo "   • Измени пароль в файле: $UI_DIR/.env"
echo "   • Настройки DNS в: $DNSCRYPT_CONF"
echo "   • Конфиг WireGuard: $WG_CONFIG"
echo
echo "✅ Готово! Твой VPN-сервер работает!"
log "Установка завершена успешно!"
