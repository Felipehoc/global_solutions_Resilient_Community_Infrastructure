#!/usr/bin/env bash
# ==============================================================================
# Política de Firewall e Segmentação Zero Trust (RT-06 e RT-07)
# Segmentos:
#   - 172.28.10.0/24 : net_iot_field (Dispositivos IoT de Campo)
#   - 172.28.20.0/24 : net_edge_autonomy (Nós de Borda Autônomos)
#   - 10.200.0.0/24  : net_vpn_tunnel (Túnel WireGuard Borda <-> Nuvem)
#   - 172.28.30.0/24 : net_cloud_core (Banco de Dados, SIEM, IA)
#   - 172.28.40.0/24 : net_supervision (Operadores Autenticados)
# ==============================================================================

set -e

# 1. Política padrão: DROP em todo tráfego de encaminhamento não autorizado explicitamente
iptables -P FORWARD DROP

# 2. Permite conexões já estabelecidas/relacionadas
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. REGRA RT-07.1: Dispositivos IoT (172.28.10.0/24) SÓ podem falar com o Broker MQTT na Borda (Porta 8883 mTLS)
iptables -A FORWARD -s 172.28.10.0/24 -d 172.28.20.0/24 -p tcp --dport 8883 -j ACCEPT
iptables -A FORWARD -s 172.28.10.0/24 -j LOG --log-prefix "[FW-BLOCK-IOT-LATERAL] "
iptables -A FORWARD -s 172.28.10.0/24 -j DROP

# 4. REGRA RT-07.2: Nós de Borda (10.200.0.2-10.200.0.6) SÓ podem sincronizar telemetria/logs via HTTPS (8443/8080) e NTP (123)
iptables -A FORWARD -s 10.200.0.0/29 -d 172.28.30.0/24 -p tcp --dport 8080 -j ACCEPT
iptables -A FORWARD -s 10.200.0.0/29 -d 172.28.30.0/24 -p udp --dport 123 -j ACCEPT
# Bloqueia acesso direto da Borda ao Banco de Dados (5432) ou SSH (22)
iptables -A FORWARD -s 10.200.0.0/29 -d 172.28.30.0/24 -p tcp -m multiport --dports 22,5432 -j DROP

# 5. REGRA RT-06 / RT-07.3: Nenhuma porta administrativa (SSH 22, DB 5432, Console SIEM) exposta à WAN/Internet
iptables -A INPUT -i eth_wan -p tcp -m multiport --dports 22,5432,8080,8883,9200 -j DROP

# 6. REGRA RT-07.4: Operadores (172.28.40.0/24) acessam apenas o Painel Web (HTTPS 443/8080), nunca dispositivos IoT diretamente
iptables -A FORWARD -s 172.28.40.0/24 -d 172.28.30.0/24 -p tcp --dport 8080 -j ACCEPT
iptables -A FORWARD -s 172.28.40.0/24 -d 172.28.10.0/24 -j DROP
