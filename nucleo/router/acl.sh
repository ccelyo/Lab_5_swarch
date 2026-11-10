#!/bin/sh
# Router interno con ACL entre la DMZ (public) y el segmento privado.
# Solo pasa gateway -> backend:8080. Todo lo demás se registra y se descarta.
set -eu

PUBLIC_NET="${PUBLIC_NET:-10.0.1.0/24}"
PRIVATE_NET="${PRIVATE_NET:-10.0.2.0/24}"
GATEWAY_IP="${GATEWAY_IP:-10.0.1.10}"
BACKEND_IP="${BACKEND_IP:-10.0.2.10}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
LOG_GROUP=1

iptables -F
iptables -X
iptables -t nat -F

# Default deny (regla 6)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Respuestas de conexiones ya permitidas
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# Regla 3: gateway (DMZ) -> backend (privado) solo en el puerto de la aplicación
iptables -A FORWARD -s "$GATEWAY_IP" -d "$BACKEND_IP" -p tcp --dport "$BACKEND_PORT" \
  -m conntrack --ctstate NEW -j ACCEPT

# Reglas 2, 5 y 6: cualquier otro flujo se registra y se descarta
iptables -A FORWARD -m limit --limit 30/min --limit-burst 60 \
  -j NFLOG --nflog-group "$LOG_GROUP" --nflog-prefix "SEG-DENY-FWD"
iptables -A FORWARD -j DROP
iptables -A INPUT -m limit --limit 30/min --limit-burst 60 \
  -j NFLOG --nflog-group "$LOG_GROUP" --nflog-prefix "SEG-DENY-IN"
iptables -A INPUT -j DROP

# Camino de vuelta: el backend ve al router (10.0.2.254) como origen,
# así los hosts privados no necesitan ruta hacia la DMZ.
iptables -t nat -A POSTROUTING -s "$PUBLIC_NET" -d "$PRIVATE_NET" -j MASQUERADE

echo "ACL cargada:"
iptables -S
iptables -t nat -S POSTROUTING

# Los intentos bloqueados salen en `docker compose logs router`
exec tcpdump -n -l -tttt -i "nflog:$LOG_GROUP"
