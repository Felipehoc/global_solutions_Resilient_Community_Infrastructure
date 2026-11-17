"""
Motor SIEM Centralizado e Regras de Detecção (RT-12 e RT-13)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Fontes centralizadas com sincronismo NTP (a.st1.ntp.br):
1. Dispositivos IoT de campo (devices)
2. Broker MQTT Mosquitto (mosquitto_edge)
3. Gateway VPN WireGuard (vpn_gateway)
4. Aplicação/Painel Web (web_panel)
5. Banco de Dados (database)
6. Sistema Operacional / Host (os_audit)

Executa em tempo real as 4 regras obrigatórias do RT-13 (equivalentes a configs/wazuh/local_rules.xml).
"""

import os
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class CentralizedSIEMEngine:
    """Coletor central de logs NTP e motor de correlação SIEM compatível com Wazuh."""

    RETENTION_POLICY = {
        "hot_storage_days": 90,
        "cold_archive_days": 365,
        "ntp_reference_stratum1": "a.st1.ntp.br",
        "clock_max_drift_ms": 15,
    }

    SQLI_PATTERN = re.compile(
        r"(?i)(UNION\s+SELECT|OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|;\s*UPDATE|;\s*DROP|sqlite_master|information_schema)"
    )

    def __init__(self, log_file_path: str = "logs/central_siem.jsonl", alerts_file_path: str = "logs/siem_alerts.jsonl"):
        self.log_file_path = log_file_path
        self.alerts_file_path = alerts_file_path
        os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
        self.ingested_logs: List[Dict[str, Any]] = []
        self.triggered_alerts: List[Dict[str, Any]] = []

    def ingest_log(self, event: Dict[str, Any], soar_orchestrator=None) -> Optional[Dict[str, Any]]:
        """
        Normaliza o log com carimbo NTP UTC, grava no repositório centralizado (RT-12)
        e avalia as 4 regras de detecção obrigatórias (RT-13).
        """
        normalized = {
            "log_seq": len(self.ingested_logs) + 1,
            "timestamp_ntp": event.get("timestamp_ntp") or datetime.now(timezone.utc).isoformat(),
            "ntp_synced": True,
            "ntp_server": self.RETENTION_POLICY["ntp_reference_stratum1"],
            "component": event.get("component", "os_audit"),
            "event_type": event.get("event_type", "generic_event"),
            "src_ip": event.get("src_ip", "127.0.0.1"),
            "user": event.get("user", "system"),
            "device_id": event.get("device_id"),
            "actuator_id": event.get("actuator_id"),
            "payload": event.get("payload", ""),
            "details": event,
        }
        self.ingested_logs.append(normalized)
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(normalized, ensure_ascii=False) + "\n")

        alert = self._evaluate_detection_rules(normalized)
        if alert:
            self.triggered_alerts.append(alert)
            with open(self.alerts_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
            if soar_orchestrator is not None:
                alert["soar_response"] = soar_orchestrator.handle_siem_alert(alert)
        return alert

    def _evaluate_detection_rules(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Avalia as 4 regras de detecção exigidas no RT-13."""
        comp = log["component"]
        ev_type = log["event_type"]
        payload = str(log.get("payload", "")) + " " + json.dumps(log.get("details", {}))

        # ---------------------------------------------------------------------
        # REGRA RT-13(a): Login VPN Anômalo (Horário de madrugada / IP externo / Falha MFA)
        # ---------------------------------------------------------------------
        if comp == "vpn_gateway" and ev_type in ("vpn_login_anomaly", "vpn_auth_suspicious", "vpn_legacy_no_mfa_login"):
            return {
                "alert_id": f"WAZUH-100710-{log['log_seq']:04d}",
                "rule_id": "100710",
                "requirement": "RT-13a",
                "severity": "HIGH (Level 12)",
                "timestamp_ntp": log["timestamp_ntp"],
                "title": "Login VPN Anomalo Detectado (IP Externo / Madrugada / Sem MFA)",
                "mitre_attack": ["T1078 - Valid Accounts", "T1133 - External Remote Services"],
                "src_ip": log["src_ip"],
                "user": log["user"],
                "source_log_seq": log["log_seq"],
            }

        # ---------------------------------------------------------------------
        # REGRA RT-13(b): Padrão de SQL Injection na Aplicação Web
        # ---------------------------------------------------------------------
        if comp in ("web_panel", "database") and (
            ev_type in ("sql_injection_blocked", "sql_injection_exploited") or self.SQLI_PATTERN.search(payload)
        ):
            return {
                "alert_id": f"WAZUH-100711-{log['log_seq']:04d}",
                "rule_id": "100711",
                "requirement": "RT-13b",
                "severity": "CRITICAL (Level 14)",
                "timestamp_ntp": log["timestamp_ntp"],
                "title": "Padrao de Ataque SQL Injection Detectado no Painel de Supervisao",
                "mitre_attack": ["T1190 - Exploit Public-Facing Application", "T1005 - Data from Local System"],
                "src_ip": log["src_ip"],
                "user": log["user"],
                "source_log_seq": log["log_seq"],
            }

        # ---------------------------------------------------------------------
        # REGRA RT-13(c): Dispositivo sem Certificado X.509 Válido ou Revogado na CRL
        # ---------------------------------------------------------------------
        if comp == "mosquitto_edge" and ev_type in ("mtls_handshake_failed", "cert_revoked_crl", "cert_missing"):
            return {
                "alert_id": f"WAZUH-100712-{log['log_seq']:04d}",
                "rule_id": "100712",
                "requirement": "RT-13c",
                "severity": "HIGH (Level 13)",
                "timestamp_ntp": log["timestamp_ntp"],
                "title": "Dispositivo IoT Rejeitado no mTLS (Sem Certificado Valido ou Revogado na CRL)",
                "mitre_attack": ["T1552.004 - Private Keys", "T1200 - Hardware Additions"],
                "device_id": log["device_id"],
                "src_ip": log["src_ip"],
                "source_log_seq": log["log_seq"],
            }

        # ---------------------------------------------------------------------
        # REGRA RT-13(d): Comando de Atuador Fora do Horário ou do Perfil Esperado
        # ---------------------------------------------------------------------
        if comp in ("edge_controller", "web_panel") and ev_type in (
            "actuator_command_anomaly",
            "unauthorized_schedule_change",
        ):
            return {
                "alert_id": f"WAZUH-100713-{log['log_seq']:04d}",
                "rule_id": "100713",
                "requirement": "RT-13d",
                "severity": "CRITICAL (Level 15)",
                "timestamp_ntp": log["timestamp_ntp"],
                "title": "Comando de Atuador Fisico Fora do Horario Esperado ou Perfil Nao Autorizado",
                "mitre_attack": ["T1565.001 - Stored Data Manipulation", "T0855 - Unauthorized Command Message"],
                "actuator_id": log["actuator_id"] or "escola-bomba-recalque-01",
                "user": log["user"],
                "src_ip": log["src_ip"],
                "source_log_seq": log["log_seq"],
            }

        return None


if __name__ == "__main__":
    engine = CentralizedSIEMEngine()
    print(json.dumps(engine.RETENTION_POLICY, indent=2, ensure_ascii=False))

