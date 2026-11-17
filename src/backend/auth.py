"""
Módulo de Autenticação Forte com MFA (TOTP RFC 6238), RBAC e Verificação de Origem VPN (RT-06, RT-09)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Perfis RBAC obrigatórios (RT-09):
- operador: Visualiza painel e telemetria, reconhece alertas simples. Não altera configurações nem aciona atuadores críticos.
- tecnico: Visualiza telemetria, executa diagnósticos e comanda atuadores dentro da janela segura.
- coordenacao: Aprova ações de alto impacto (Human-in-the-loop RT-15), gerencia voluntários e agenda de bombas.
- auditor: Acesso somente-leitura aos logs centralizados, trilha de auditoria, evidências forenses e métricas.
"""

import time
import hmac
import base64
import struct
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List


class RBACAndMFAManager:
    """Gerencia autenticação multifator TOTP (RFC 6238) e controle de acesso baseado em papéis (RBAC)."""

    ROLE_PERMISSIONS = {
        "operador": {
            "view_dashboard",
            "ack_low_alert",
            "report_phishing",
        },
        "tecnico": {
            "view_dashboard",
            "ack_low_alert",
            "report_phishing",
            "operate_safe_actuator",
            "rotate_device_cert",
        },
        "coordenacao": {
            "view_dashboard",
            "ack_low_alert",
            "report_phishing",
            "operate_safe_actuator",
            "approve_high_impact_action",
            "manage_pump_schedule",
            "revoke_device_cert",
        },
        "auditor": {
            "view_dashboard",
            "view_audit_logs",
            "view_forensic_evidence",
            "export_compliance_report",
        },
    }

    SYNTHETIC_ACCOUNTS = {
        "operador01": {
            "username": "operador01",
            "password_sha256": hashlib.sha256(b"VilaAurora#Op2026!").hexdigest(),
            "role": "operador",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "allowed_subnets": ["10.200.0.", "172.28.40.", "127.0.0.1"],
        },
        "tecnico02": {
            "username": "tecnico02",
            "password_sha256": hashlib.sha256(b"VilaAurora#Tec2026!").hexdigest(),
            "role": "tecnico",
            "totp_secret": "JBSWY3DPEHPK3PXQ",
            "allowed_subnets": ["10.200.0.", "172.28.40.", "127.0.0.1"],
        },
        "coordenacao03": {
            "username": "coordenacao03",
            "password_sha256": hashlib.sha256(b"VilaAurora#Coord2026!").hexdigest(),
            "role": "coordenacao",
            "totp_secret": "JBSWY3DPEHPK3PXR",
            "allowed_subnets": ["10.200.0.", "127.0.0.1"],  # Admin exige VPN (10.200.0.x)
        },
        "auditor04": {
            "username": "auditor04",
            "password_sha256": hashlib.sha256(b"VilaAurora#Audit2026!").hexdigest(),
            "role": "auditor",
            "totp_secret": "JBSWY3DPEHPK3PXS",
            "allowed_subnets": ["10.200.0.", "172.28.40.", "127.0.0.1"],
        },
    }

    @staticmethod
    def generate_totp_token(secret_base32: str, timestamp: int = None, interval: int = 30) -> str:
        """Gera token TOTP de 6 dígitos compatível com RFC 6238 (Google Authenticator / FreeOTP)."""
        ts = int(timestamp if timestamp is not None else time.time())
        counter = ts // interval
        missing_padding = len(secret_base32) % 8
        if missing_padding:
            secret_base32 += "=" * (8 - missing_padding)
        key = base64.b32decode(secret_base32.upper(), casefold=True)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[19] & 0x0F
        code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"

    def authenticate_operator(
        self, username: str, password: str, totp_code: str, client_ip: str = "10.200.0.50", timestamp: int = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Valida credenciais + MFA TOTP + Origem de Rede VPN (RT-06, RT-09).
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        account = self.SYNTHETIC_ACCOUNTS.get(username)
        if not account:
            return False, "AUTH_FAILED_INVALID_USER", {"timestamp_ntp": now_iso, "user": username, "src_ip": client_ip}

        # Verifica se o acesso administrativo parte da VPN WireGuard (RT-06)
        if not any(client_ip.startswith(prefix) for prefix in account["allowed_subnets"]):
            return (
                False,
                "BLOCKED_NON_VPN_ORIGIN",
                {
                    "timestamp_ntp": now_iso,
                    "component": "vpn_gateway",
                    "event_type": "vpn_login_anomaly",
                    "user": username,
                    "src_ip": client_ip,
                    "reason": "Tentativa de acesso fora da sub-rede VPN WireGuard 10.200.0.0/24",
                },
            )

        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(pwd_hash, account["password_sha256"]):
            return False, "AUTH_FAILED_BAD_PASSWORD", {"timestamp_ntp": now_iso, "user": username, "src_ip": client_ip}

        expected_totp = self.generate_totp_token(account["totp_secret"], timestamp=timestamp)
        if not totp_code or not hmac.compare_digest(str(totp_code).strip(), expected_totp):
            return (
                False,
                "AUTH_FAILED_MFA_REQUIRED_OR_INVALID",
                {
                    "timestamp_ntp": now_iso,
                    "component": "vpn_gateway",
                    "event_type": "vpn_auth_suspicious",
                    "user": username,
                    "src_ip": client_ip,
                    "reason": "Token MFA TOTP ausente ou invalido",
                },
            )

        return (
            True,
            "AUTH_SUCCESS_WITH_MFA",
            {
                "timestamp_ntp": now_iso,
                "user": username,
                "role": account["role"],
                "src_ip": client_ip,
                "mfa_verified": True,
                "permissions": sorted(list(self.ROLE_PERMISSIONS[account["role"]])),
            },
        )

    def check_permission(self, role: str, action: str) -> Tuple[bool, str]:
        """Verifica se o perfil RBAC possui permissão para a ação solicitada (RT-09)."""
        perms = self.ROLE_PERMISSIONS.get(role, set())
        if action in perms:
            return True, f"RBAC_ALLOWED: Perfil '{role}' possui permissao '{action}'."
        return False, f"RBAC_DENIED: Perfil '{role}' NAO possui permissao para '{action}' (Menor Privilegio)."
