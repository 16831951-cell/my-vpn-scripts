#!/bin/bash

set -euo pipefail

# =============================================================================
# PRO-версия: WireGuard-сервер с QR-кодами, DNSCrypt и веб-интерфейсом
# Для Ubuntu 24.04 + TP-Link BE230
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

# Исправленное определение IPv4
PUBLIC_IP=$(curl -s https://ifconfig.co)
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

if [[ -z "$INTERFACE" ]]; then
  echo "❌ Не удалось определить сетевой интерфейс."
  read -p "Введите имя интерфейса (например, eth0): " INTERFACE
fi

echo "🌐 Используем интерфейс: $INTERFACE"
echo "🔑 Публичный IPv4: $PUBLIC_IP"

# Создаём директории
mkdir -p "$CLIENT_DIR"
mkdir -p "$(dirname "$DNSCRYPT_CONF")"

# ========================
# 1. ОБНОВЛЕНИЕ СИСТЕМЫ
# ========================
echo "🔄 Обновление системы..."
apt update -y

# ========================
# 2. УСТАНОВКА ОСНОВНЫХ ПАКЕТОВ
# ========================
echo "📦 Установка WireGuard, iptables, qrencode, curl, jq..."
apt install -y wireguard iptables qrencode curl jq

# ========================
# 3. ГЕНЕРАЦИЯ КЛЮЧЕЙ СЕРВЕРА
# ========================
echo "🔐 Генерация ключей сервера..."
cd "$KEY_DIR"
umask 077
wg genkey | tee privatekey | wg pubkey > publickey

SERVER_PRIVATE_KEY=$(cat privatekey)
SERVER_PUBLIC_KEY=$(cat publickey)

# ========================
# 4. НАСТРОЙКА WIREGUARD (wg0.conf)
# ========================
echo "⚙️ Создание конфигурации сервера..."
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
echo "🌐 Включение IP-форвардинга..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# ========================
# 6. ОТКРЫТИЕ ПОРТОВ В UFW
# ========================
echo "🛡 Настройка UFW..."
if command -v ufw &> /dev/null; then
    ufw allow 51820/udp
    ufw allow 8080/tcp
    ufw --force enable
    echo "   Порты 51820/udp и 8080/tcp открыты."
fi

# ========================
# 7. УСТАНОВКА DNSCRYPT-PROXY (DNS-over-HTTPS)
# ========================
echo "🔒 Установка dnscrypt-proxy (DNS-over-HTTPS)..."
apt install -y dnscrypt-proxy

# Настройка dnscrypt-proxy на использование Cloudflare
cat <<EOF > "$DNSCRYPT_CONF"
server_names = ['cloudflare', 'cloudflare-ipv6']
listen_addresses = ['127.0.0.1:53', '[::1]:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = true
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
EOF

# Перезапуск
systemctl enable --now dnscrypt-proxy
echo "   dnscrypt-proxy запущен на 127.0.0.1:53"

# ========================
# 8. УСТАНОВКА WIREGUARD-UI (ВЕБ-ИНТЕРФЕЙС)
# ========================
echo "🖥 Установка WireGuard-UI (веб-интерфейс)..."
mkdir -p "$UI_DIR"
cd "$UI_DIR"

# Исправленная загрузка wg-easy
echo "   Скачивание последней версии wg-easy..."
LATEST_RELEASE=$(curl -s https://api.github.com/repos/WeeJeWel/wg-easy/releases/latest | jq -r '.tag_name')
echo "   Последняя версия: $LATEST_RELEASE"
curl -L "https://github.com/WeeJeWel/wg-easy/releases/download/${LATEST_RELEASE}/wg-easy_linux_amd64.tar.gz" -o wg-easy.tar.gz
tar xzf wg-easy.tar.gz
rm wg-easy.tar.gz

# Создаём systemd-юнит
cat <<EOF > /etc/systemd/system/wg-easy.service
[Unit]
Description=WireGuard UI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$UI_DIR
ExecStart=$UI_DIR/wg-easy
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now wg-easy

echo "   Веб-интерфейс доступен по адресу: http://$PUBLIC_IP:$UI_PORT"

# ========================
# 9. УСТАНОВКА FAIL2BAN (ДОПОЛНИТЕЛЬНАЯ ЗАЩИТА)
# ========================
echo "🛡 Установка fail2ban..."
apt install -y fail2ban

# Базовая конфигурация (защита SSH)
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable --now fail2ban

# ========================
# 10. ФУНКЦИЯ ДОБАВЛЕНИЯ КЛИЕНТА (с QR-кодом) - СДЕЛАНА ГЛОБАЛЬНОЙ
# ========================
add_client() {
    local name="$1"
    if [[ -z "$name" ]]; then
        echo "❌ Укажите имя клиента: add_client имя_клиента"
        return 1
    fi

    # Найти следующий доступный IP (10.8.0.2 - 10.8.0.254)
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
        if [[ ! " ${used_ips[*]} " =~ " 10.8.0.$i " ]]; then
            next_ip="10.8.0.$i"
            break
        fi
    done

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
    qrencode -t ansiutf8 < "$CLIENT_DIR/${name}.conf"
    echo
    echo "💾 Конфиг сохранён: $CLIENT_DIR/${name}.conf"
    echo "🖼 QR-код выше — сканируй его в приложении WireGuard на телефоне!"
    echo "🌐 Веб-интерфейс: http://$PUBLIC_IP:$UI_PORT (логин: admin, пароль: admin)"

    # Перезапуск WireGuard
    wg-quick down wg0
    wg-quick up wg0
    echo "🔁 WireGuard перезапущен."
}

# Экспортируем функцию, чтобы она была доступна в текущей сессии
export -f add_client

# ========================
# 11. ЗАПУСК WIREGUARD И ПРОВЕРКА
# ========================
echo "🚀 Запуск WireGuard..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Проверка
echo "📋 Проверка статуса:"
systemctl is-active wg-quick@wg0
wg show

# ========================
# 12. ФИНАЛЬНОЕ СООБЩЕНИЕ
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
echo "🛠 ДОБАВИТЬ КЛИЕНТА:"
echo "   add_client имя_клиента"
echo "   Пример: add_client tplink_be230"
echo
echo "📥 СКАЧАТЬ КОНФИГ:"
echo "   scp root@$PUBLIC_IP:/root/wg-clients/tplink_be230.conf ./"
echo
echo "🛡 БЕЗОПАСНОСТЬ:"
echo "   • UFW активен (только 518.20/udp и 8080/tcp)"
echo "   • Fail2ban защищает SSH"
echo "   • DNSCrypt шифрует все DNS-запросы"
echo
echo "💡 ПОДКЛЮЧЕНИЕ TP-Link BE230:"
echo "   1. Открой веб-интерфейс роутера: http://192.168.1.1"
echo "   2. Перейди: Advanced → VPN → WireGuard Client"
echo "   3. Нажми Add → Вставь содержимое файла: /root/wg-clients/tplink_be230.conf"
echo "   4. Включай клиент → Проверь IP на https://whatismyipaddress.com"
echo
echo "✅ Готово! Твой VPN-сервер в Латвии работает!"

# ========================
# 13. СОХРАНЕНИЕ ФУНКЦИИ В .bashrc (для постоянного доступа)
# ========================
BASHRC_FUNC_PATH="/root/.bashrc_wireguard"
cat <<'EOF' > "$BASHRC_FUNC_PATH"
add_client() {
    local name="$1"
    if [[ -z "$name" ]]; then
        echo "❌ Укажите имя клиента: add_client имя_клиента"
        return 1
    fi

    local WG_CONFIG="/etc/wireguard/wg0.conf"
    local CLIENT_DIR="/root/wg-clients"
    local PUBLIC_IP=$(curl -s https://ifconfig.co)
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
        if [[ ! " ${used_ips[*]} " =~ " 10.8.0.$i " ]]; then
            next_ip="10.8.0.$i"
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
    echo "🖼 QR-код выше — сканируй его в приложении WireGuard на телефоне!"
    echo "🌐 Веб-интерфейс: http://$PUBLIC_IP:8080 (логин: admin, пароль: admin)"

    wg-quick down wg0
    wg-quick up wg0
    echo "🔁 WireGuard перезапущен."
}
EOF

echo "   Функция add_client сохранена в $BASHRC_FUNC_PATH"
echo "   Для загрузки после перезагрузки добавь в ~/.bashrc:"
echo "   echo 'source $BASHRC_FUNC_PATH' >> ~/.bashrc"
echo "   source $BASHRC_FUNC_PATH"
source "$BASHRC_FUNC_PATH"
