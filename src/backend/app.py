"""
Backend Principal Integrado em Tempo Real (RT-01 a RT-23)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Conecta o Painel Web Acessível (WCAG 2.1 AA) diretamente aos motores reais em Python:
- PKI X.509, verificação mTLS, Revogação CRL e Rotação (`VilaAuroraPKIManager` - RT-04, RT-05)
- Simulador de Campo dos 5 Espaços (`VilaAuroraFieldSimulator` - RT-01)
- Nó de Borda Autônomo com Buffer SQLite Store-and-Forward real (`EdgeAutonomousNode` - RT-02, RT-03)
- Banco de Dados Core com Pseudonimização LGPD e Demonstração SQLi Antes/Depois (`RT-08, RT-19`)
- Autenticação MFA TOTP RFC 6238 real e RBAC de 4 perfis (`RBACAndMFAManager` - RT-06, RT-09)
- Simulação Ética de Phishing e Validação DNS SPF/DKIM/DMARC (`RT-10, RT-11, RT-18`)
- Motor SIEM Centralizado NTP + 4 Regras Wazuh ao vivo (`CentralizedSIEMEngine` - RT-12, RT-13)
- Orquestrador SOAR com fila real de aprovação humana (`SOARPlaybookOrchestrator` - RT-15)
- IA Defensiva Isolation Forest (`TelemetryAnomalyDetector` - RT-16) + Guardrails LLM (`OperatorTriageLLMWithGuardrails` - RT-17)
"""

import os
import re
import sys
import json
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

# Garante que a raiz do projeto esteja no sys.path mesmo executando `python src/backend/app.py` diretamente
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.pki.pki_manager import VilaAuroraPKIManager
from src.field_simulators.iot_simulator import VilaAuroraFieldSimulator
from src.edge_node.autonomous_agent import EdgeAutonomousNode
from src.backend.privacy import LGPDPrivacyManager
from src.backend.auth import RBACAndMFAManager
from src.siem_soar.siem_engine import CentralizedSIEMEngine
from src.siem_soar.soar_playbook import SOARPlaybookOrchestrator
from src.ai_defense.anomaly_detector import TelemetryAnomalyDetector
from src.ai_defense.llm_guardrails import OperatorTriageLLMWithGuardrails
from scripts.run_phishing_simulation import run_phishing_and_email_security_suite


class VilaAuroraApplicationBackend:
    """Backend integrado da Rede Comunitária Vila Aurora (100% Funcional no Servidor)."""

    WAF_SQLI_REGEX = re.compile(
        r"(?i)(\bUNION\b\s+\bSELECT\b|\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bDROP\b\s+\bTABLE\b|;\s*\bUPDATE\b|;\s*\bINSERT\b|--|/\*|\bsqlite_master\b|\binformation_schema\b)"
    )
    SAFE_SEARCH_REGEX = re.compile(r"^[a-zA-Z0-9_\-\s]{1,40}$")

    def __init__(self, db_path: str = "data/vila_aurora_core.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.privacy = LGPDPrivacyManager()
        self.auth = RBACAndMFAManager()
        self.pki = VilaAuroraPKIManager()
        self.pki.provision_all_community_devices()
        self.pki.revoke_certificate("sensor-comprometido-99", reason="compromisedKeyLab")

        self.simulator = VilaAuroraFieldSimulator(seed=42)
        self.edge_node = EdgeAutonomousNode(buffer_db_path="data/edge_buffers/edge_store_and_forward.db")
        self.siem = CentralizedSIEMEngine()
        self.soar = SOARPlaybookOrchestrator(pki_manager=self.pki, auth_manager=self.auth)
        self.ai_detector = TelemetryAnomalyDetector(random_seed=42)
        self.ai_metrics_cache = self.ai_detector.fit_and_evaluate()
        self.llm_guardrails = OperatorTriageLLMWithGuardrails()

        self.security_events: List[Dict[str, Any]] = []
        self._init_database()
        self._seed_initial_siem_and_soar_state()

    def _init_database(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS operators_credentials (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    space_assigned TEXT NOT NULL,
                    is_synthetic INTEGER DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pump_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    space TEXT NOT NULL,
                    actuator_id TEXT NOT NULL,
                    cron_window TEXT NOT NULL,
                    max_duration_minutes INTEGER NOT NULL,
                    updated_by TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS access_logs (
                    log_id TEXT PRIMARY KEY,
                    timestamp_ntp TEXT NOT NULL,
                    pseudonym_token TEXT NOT NULL,
                    role_profile TEXT NOT NULL,
                    space TEXT NOT NULL,
                    door_or_resource TEXT NOT NULL,
                    event_result TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_telemetry_history (
                    event_id TEXT PRIMARY KEY,
                    timestamp_ntp TEXT NOT NULL,
                    space TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    rule_action TEXT
                )
                """
            )
            conn.execute("DROP VIEW IF EXISTS v_public_access_history")
            conn.execute(
                """
                CREATE VIEW v_public_access_history AS
                SELECT log_id, timestamp_ntp, pseudonym_token, role_profile, space, door_or_resource, event_result
                FROM access_logs
                """
            )

            for vol in self.privacy.SYNTHETIC_VOLUNTEERS:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO operators_credentials
                    (user_id, username, role, password_hash, space_assigned, is_synthetic)
                    VALUES (?, ?, ?, ?, ?, 1)
                    """,
                    (
                        vol["synthetic_id"],
                        vol["email_synthetic"].split("@")[0],
                        vol["role"],
                        f"pbkdf2_sha256$260000${self.privacy.pseudonymize_identifier(vol['synthetic_id'])}",
                        vol["space_assigned"],
                    ),
                )

            conn.execute(
                """
                INSERT OR REPLACE INTO pump_schedules
                (schedule_id, space, actuator_id, cron_window, max_duration_minutes, updated_by)
                VALUES ('SCHED-ESC-01', 'Escola_Municipal', 'escola-bomba-recalque-01', '07:00-18:00', 45, 'coordenacao03')
                """
            )

            sample_logs = [
                {
                    "log_id": "LOG-2026-001",
                    "timestamp_ntp": "2026-11-15T10:15:00Z",
                    "badge_rfid_raw": "RFID-VA-9001-SINT",
                    "role": "operador",
                    "space": "Escola_Municipal",
                    "door_or_resource": "Casa_de_Bombas_Escola",
                    "event_result": "GRANTED",
                },
                {
                    "log_id": "LOG-2026-002",
                    "timestamp_ntp": "2026-11-15T11:30:00Z",
                    "badge_rfid_raw": "RFID-VA-9002-SINT",
                    "role": "tecnico",
                    "space": "UBS",
                    "door_or_resource": "Sala_Camara_Fria_Vacinas",
                    "event_result": "GRANTED",
                },
                {
                    "log_id": "LOG-2026-003",
                    "timestamp_ntp": "2026-11-15T14:20:00Z",
                    "badge_rfid_raw": "RFID-VA-9004-SINT",
                    "role": "auditor",
                    "space": "Abrigo_Emergencia",
                    "door_or_resource": "Deposito_Defesa_Civil",
                    "event_result": "GRANTED",
                },
            ]
            for raw_log in sample_logs:
                sanitized = self.privacy.sanitize_access_log_record(raw_log)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO access_logs
                    (log_id, timestamp_ntp, pseudonym_token, role_profile, space, door_or_resource, event_result)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sanitized["log_id"],
                        sanitized["timestamp_ntp"],
                        sanitized["pseudonym_token"],
                        sanitized["role_profile"],
                        sanitized["space"],
                        sanitized["door_or_resource"],
                        sanitized["event_result"],
                    ),
                )
            conn.commit()

    def _seed_initial_siem_and_soar_state(self) -> None:
        """Popula as 4 regras base do SIEM e a fila SOAR para inspeção imediata."""
        # Limpa arquivo de sessão ao iniciar o servidor para manter a lista limpa e rastreável
        for path in (self.siem.log_file_path, self.siem.alerts_file_path):
            if os.path.exists(path):
                os.remove(path)

        initial_events = [
            {
                "timestamp_ntp": "2026-10-26T02:14:03Z",
                "component": "vpn_gateway",
                "event_type": "vpn_login_anomaly",
                "src_ip": "198.51.100.99",
                "user": "coordenacao03",
                "payload": "Login VPN na madrugada (02h14) a partir de IP externo desconhecido sem MFA.",
            },
            {
                "timestamp_ntp": "2026-10-26T02:17:29Z",
                "component": "web_panel",
                "event_type": "sql_injection_exploited",
                "src_ip": "198.51.100.99",
                "user": "coordenacao03",
                "payload": "xyz%' UNION SELECT user_id, username, role, password_hash, space_assigned FROM operators_credentials --",
            },
            {
                "timestamp_ntp": "2026-10-26T02:19:44Z",
                "component": "edge_controller",
                "event_type": "actuator_command_anomaly",
                "src_ip": "198.51.100.99",
                "user": "coordenacao03",
                "actuator_id": "escola-bomba-recalque-01",
                "payload": "Alteracao maliciosa do agendamento da bomba de agua da Escola na madrugada.",
            },
            {
                "timestamp_ntp": "2026-10-26T02:22:15Z",
                "component": "mosquitto_edge",
                "event_type": "cert_revoked_crl",
                "src_ip": "172.28.10.99",
                "device_id": "sensor-comprometido-99",
                "payload": "Handshake mTLS rejeitado: certificado consta na CRL (crl.pem).",
            },
        ]
        for ev in initial_events:
            self.siem.ingest_log(ev, soar_orchestrator=self.soar)

    def trigger_custom_siem_rule(self, rule_code: str) -> Dict[str, Any]:
        """Permite disparar manualmente qualquer uma das 4 regras do SIEM (RT-13a..d) pelo Painel Web."""
        now_iso = datetime.now(timezone.utc).isoformat()
        events_map = {
            "RT-13a": {
                "timestamp_ntp": now_iso,
                "component": "vpn_gateway",
                "event_type": "vpn_login_anomaly",
                "src_ip": "203.0.113.88",
                "user": "operador01",
                "payload": "Tentativa de login VPN sem MFA a partir de IP externo nao autorizado.",
            },
            "RT-13b": {
                "timestamp_ntp": now_iso,
                "component": "web_panel",
                "event_type": "sql_injection_blocked",
                "src_ip": "203.0.113.88",
                "user": "anonymous",
                "payload": "' UNION SELECT username, password_hash FROM operators_credentials --",
            },
            "RT-13c": {
                "timestamp_ntp": now_iso,
                "component": "mosquitto_edge",
                "event_type": "cert_revoked_crl",
                "src_ip": "172.28.10.99",
                "device_id": "sensor-comprometido-99",
                "payload": "Conexao MQTT mTLS recusada pelo Broker: serial consta na CRL.",
            },
            "RT-13d": {
                "timestamp_ntp": now_iso,
                "component": "edge_controller",
                "event_type": "actuator_command_anomaly",
                "src_ip": "10.200.0.50",
                "user": "operador01",
                "actuator_id": "escola-bomba-recalque-01",
                "payload": "Tentativa de acionamento continuo da bomba de recalque as 03h15 (fora da janela segura).",
            },
        }
        ev = events_map.get(rule_code, events_map["RT-13a"])
        alert = self.siem.ingest_log(ev, soar_orchestrator=self.soar)
        return {
            "triggered_alert": alert,
            "total_alerts": len(self.siem.triggered_alerts),
            "recent_alerts": list(reversed(self.siem.triggered_alerts[-10:])),
        }

    def _save_cloud_telemetry(self, reading: Dict[str, Any], rule_action: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_telemetry_history
                (event_id, timestamp_ntp, space, device_id, metric, value, unit, rule_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reading["event_id"],
                    reading["timestamp_ntp"],
                    reading["space"],
                    reading["device_id"],
                    reading["metric"],
                    float(reading["value"]),
                    reading["unit"],
                    rule_action,
                ),
            )
            conn.commit()

    def _save_cloud_batch(self, records: List[Dict[str, Any]]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            for r in records:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cloud_telemetry_history
                    (event_id, timestamp_ntp, space, device_id, metric, value, unit, rule_action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r["event_id"],
                        r["timestamp_ntp"],
                        r["space"],
                        r["device_id"],
                        r["metric"],
                        float(r["value"]),
                        r["unit"],
                        r.get("local_rule_action", "RECONCILED"),
                    ),
                )
            conn.commit()

    def run_live_telemetry_cycle(self, inject_anomalies: bool = False) -> Dict[str, Any]:
        batch = self.simulator.generate_telemetry_batch(inject_anomalies=inject_anomalies)
        processed_items = []

        for r in batch:
            mtls_ok, mtls_status, _ = self.pki.verify_mtls_connection(r["device_id"])
            if not mtls_ok:
                continue
            edge_res = self.edge_node.ingest_reading(r, cloud_callback=self._save_cloud_telemetry)
            if edge_res["local_rule_action"] != "NORMAL_LOCAL_OPERATION":
                self.siem.ingest_log(
                    {
                        "component": "edge_controller",
                        "event_type": "actuator_command_anomaly",
                        "device_id": r["device_id"],
                        "actuator_id": r["device_id"],
                        "user": "edge_autonomous_rule",
                        "payload": edge_res["local_rule_action"],
                    },
                    soar_orchestrator=self.soar,
                )
            processed_items.append(
                {
                    **r,
                    "mtls_status": mtls_status,
                    "local_rule_action": edge_res["local_rule_action"],
                    "buffered_offline": edge_res["buffered_offline"],
                }
            )

        with sqlite3.connect(self.edge_node.buffer_db_path) as conn:
            pending_count = conn.execute("SELECT COUNT(*) FROM telemetry_buffer WHERE synced_to_cloud = 0").fetchone()[0]
            total_edge_count = conn.execute("SELECT COUNT(*) FROM telemetry_buffer").fetchone()[0]

        with sqlite3.connect(self.db_path) as conn:
            total_cloud_count = conn.execute("SELECT COUNT(*) FROM cloud_telemetry_history").fetchone()[0]

        return {
            "timestamp_ntp": datetime.now(timezone.utc).isoformat(),
            "wan_connected": self.edge_node.wan_connected,
            "spaces_link_state": self.edge_node.set_wan_status(self.edge_node.wan_connected)["spaces_link_state"],
            "edge_sqlite_pending_buffer": pending_count,
            "edge_sqlite_total_records": total_edge_count,
            "cloud_db_total_reconciled": total_cloud_count,
            "readings": processed_items,
            "recent_local_alarms": self.edge_node.local_alarms_triggered[-5:],
            "total_siem_alerts": len(self.siem.triggered_alerts),
        }

    def toggle_wan_and_reconcile(self, set_online: bool) -> Dict[str, Any]:
        link_report = self.edge_node.set_wan_status(set_online)
        reconciliation = None

        if not set_online:
            for _ in range(3):
                self.run_live_telemetry_cycle(inject_anomalies=False)
        else:
            reconciliation = self.edge_node.synchronize_pending_buffer(cloud_sync_receiver=self._save_cloud_batch)

        state = self.run_live_telemetry_cycle(inject_anomalies=False)
        state["reconciliation_report"] = reconciliation
        state["link_report"] = link_report
        return state

    def search_access_logs_vulnerable_legacy(self, query_filter: str, client_ip: str = "198.51.100.99") -> Dict[str, Any]:
        raw_sql = (
            f"SELECT log_id, timestamp_ntp, space, door_or_resource, event_result "
            f"FROM access_logs WHERE space LIKE '%{query_filter}%'"
        )
        try:
            with sqlite3.connect(self.db_path) as conn:
                if ";" in query_filter and "UPDATE pump_schedules" in query_filter:
                    conn.executescript(raw_sql)
                    conn.commit()
                    rows = []
                else:
                    cursor = conn.execute(raw_sql)
                    rows = [
                        {
                            "col_1": r[0],
                            "col_2": r[1],
                            "col_3": r[2],
                            "col_4": r[3],
                            "col_5": r[4],
                        }
                        for r in cursor.fetchall()
                    ]
                return {
                    "mode": "VULNERABLE_LEGACY_PAINEL",
                    "status": "EXECUTED_UNSAFE_QUERY",
                    "executed_sql_exposed": raw_sql,
                    "records_returned": len(rows),
                    "data": rows,
                }
        except Exception as exc:
            return {
                "mode": "VULNERABLE_LEGACY_PAINEL",
                "status": "DB_EXCEPTION_LEAKED",
                "leaked_db_error": str(exc),
                "executed_sql_exposed": raw_sql,
            }

    def search_access_logs_secure(self, query_filter: str, client_ip: str = "10.200.0.50") -> Tuple[int, Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()

        if self.WAF_SQLI_REGEX.search(query_filter or ""):
            alert_event = {
                "timestamp_ntp": now_iso,
                "component": "web_panel",
                "event_type": "sql_injection_blocked",
                "endpoint": "/api/v1/access-logs/search",
                "src_ip": client_ip,
                "payload": query_filter[:120],
                "action": "BLOCKED_BY_WAF_AND_PARAMETERIZATION",
            }
            self.security_events.append(alert_event)
            self.siem.ingest_log(alert_event, soar_orchestrator=self.soar)
            return (
                403,
                {
                    "status": "BLOCKED_BY_SECURITY_POLICY",
                    "message": "Requisicao bloqueada pelo WAF + Prepared Statement. Alerta SIEM WAZUH-100711 registrado em logs/siem_alerts.jsonl.",
                    "reference_id": f"SEC-{len(self.security_events):04d}",
                    "total_siem_alerts_now": len(self.siem.triggered_alerts),
                },
            )

        cleaned = (query_filter or "").strip()
        if not self.SAFE_SEARCH_REGEX.match(cleaned):
            return (
                400,
                {
                    "status": "INVALID_INPUT",
                    "message": "Filtro de busca invalido. Utilize apenas letras, numeros, espacos ou sublinhado (max 40 caracteres).",
                },
            )

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT log_id, timestamp_ntp, pseudonym_token, role_profile, space, door_or_resource, event_result
                    FROM v_public_access_history
                    WHERE space LIKE ? OR door_or_resource LIKE ?
                    ORDER BY timestamp_ntp DESC
                    LIMIT 50
                    """,
                    (f"%{cleaned}%", f"%{cleaned}%"),
                )
                rows = [dict(r) for r in cursor.fetchall()]
                return (
                    200,
                    {
                        "status": "OK",
                        "query_parameterized": True,
                        "least_privilege_view": "v_public_access_history",
                        "records_returned": len(rows),
                        "data": rows,
                    },
                )
        except Exception:
            return (
                500,
                {
                    "status": "INTERNAL_ERROR",
                    "message": "Nao foi possivel processar a consulta no momento. Contate o suporte tecnico.",
                },
            )


def create_http_handler(backend: VilaAuroraApplicationBackend):
    """Handler HTTP que conecta todos os controles do Painel Web ao Backend Python real."""

    class VilaAuroraRequestHandler(BaseHTTPRequestHandler):
        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            if parsed.path in ("/", "/index.html"):
                html_path = os.path.join("src", "frontend", "index.html")
                if os.path.exists(html_path):
                    with open(html_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(content)
                    return

            if parsed.path == "/api/v1/telemetry/live":
                anom = qs.get("anomaly", ["0"])[0] == "1"
                data = backend.run_live_telemetry_cycle(inject_anomalies=anom)
                self._send_json(200, data)
                return

            if parsed.path == "/api/v1/edge/wan-toggle":
                online = qs.get("online", ["1"])[0] == "1"
                data = backend.toggle_wan_and_reconcile(set_online=online)
                self._send_json(200, data)
                return

            if parsed.path == "/api/v1/access-logs/search":
                q = qs.get("q", ["UBS"])[0]
                code, resp = backend.search_access_logs_secure(q, client_ip=self.client_address[0])
                self._send_json(code, resp)
                return

            if parsed.path == "/api/v1/sqli-compare":
                q = qs.get("q", ["UBS"])[0]
                legacy_res = backend.search_access_logs_vulnerable_legacy(q, client_ip=self.client_address[0])
                sec_code, sec_res = backend.search_access_logs_secure(q, client_ip=self.client_address[0])
                self._send_json(
                    200,
                    {
                        "query": q,
                        "legacy_vulnerable": legacy_res,
                        "secure_remediated_http_code": sec_code,
                        "secure_remediated": sec_res,
                        "recent_siem_alerts": list(reversed(backend.siem.triggered_alerts[-10:])),
                    },
                )
                return

            if parsed.path == "/api/v1/auth/totp":
                user = qs.get("user", ["coordenacao03"])[0]
                acct = backend.auth.SYNTHETIC_ACCOUNTS.get(user, backend.auth.SYNTHETIC_ACCOUNTS["coordenacao03"])
                real_token = backend.auth.generate_totp_token(acct["totp_secret"])
                self._send_json(
                    200,
                    {
                        "user": user,
                        "role": acct["role"],
                        "totp_token_rfc6238": real_token,
                        "valid_window_seconds": 30,
                    },
                )
                return

            if parsed.path == "/api/v1/soar/decide":
                role = qs.get("role", ["coordenacao"])[0]
                codeword = qs.get("codeword", [""])[0].strip()
                totp = qs.get("totp", [""])[0].strip()
                decision = qs.get("decision", ["REJECT"])[0].upper()

                if decision == "REJECT":
                    res = backend.soar.process_human_decision(
                        "APPROVAL-001", "operador_humano", "", "", decision="REJECT"
                    )
                    self._send_json(200, {"allowed": True, "decision": "REJECTED", "soar_record": res})
                    return

                rbac_ok, rbac_msg = backend.auth.check_permission(role, "approve_high_impact_action")
                if not rbac_ok:
                    self._send_json(403, {"allowed": False, "error_type": "RBAC_DENIED", "message": rbac_msg})
                    return

                if codeword.lower() not in ("ipe-amarelo", "ipê-amarelo"):
                    self._send_json(
                        403,
                        {
                            "allowed": False,
                            "error_type": "VOICE_CLONE_CODEWORD_INVALID",
                            "message": "Palavra-Codigo Semanal incorreta! Protecao contra golpe de voz clonada (RT-18).",
                        },
                    )
                    return

                res = backend.soar.process_human_decision(
                    "APPROVAL-001", "coordenacao03", "VilaAurora#Coord2026!", totp, decision="APPROVE"
                )
                if res.get("status") == "DENIED_MFA_FAILED":
                    self._send_json(
                        401,
                        {
                            "allowed": False,
                            "error_type": "MFA_INVALID",
                            "message": "Token TOTP invalido ou expirado! Clique em 'Gerar Token MFA Agora'.",
                        },
                    )
                    return

                self._send_json(200, {"allowed": True, "decision": "APPROVED", "soar_record": res})
                return

            if parsed.path == "/api/v1/siem/trigger":
                rule = qs.get("rule", ["RT-13a"])[0]
                res = backend.trigger_custom_siem_rule(rule)
                self._send_json(200, res)
                return

            if parsed.path == "/api/v1/pki/action":
                action = qs.get("action", ["verify"])[0]
                dev = qs.get("device", ["escola-bomba-recalque-01"])[0]
                if action == "rotate":
                    rot = backend.pki.rotate_device_certificate(dev, reason="manualDashboardRotation")
                    self._send_json(200, {"action": "ROTATED", "details": rot})
                    return
                if action == "verify_revoked":
                    ok, msg, ev = backend.pki.verify_mtls_connection("sensor-comprometido-99")
                    backend.siem.ingest_log(ev, soar_orchestrator=backend.soar)
                    self._send_json(
                        200,
                        {
                            "action": "VERIFIED_REVOKED",
                            "allowed": ok,
                            "status": msg,
                            "event": ev,
                            "total_alerts": len(backend.siem.triggered_alerts),
                        },
                    )
                    return
                ok, msg, ev = backend.pki.verify_mtls_connection(dev)
                self._send_json(200, {"action": "VERIFIED_VALID", "allowed": ok, "status": msg, "event": ev})
                return

            if parsed.path == "/api/v1/phishing/run":
                phish_data = run_phishing_and_email_security_suite()
                self._send_json(200, phish_data)
                return

            if parsed.path == "/api/v1/llm/triage":
                prompt = qs.get("prompt", [""])[0]
                context = qs.get("context", [""])[0]
                result = backend.llm_guardrails.process_triage_request(prompt, context)
                self._send_json(200, result)
                return

            if parsed.path == "/api/v1/siem/status":
                self._send_json(
                    200,
                    {
                        "total_alerts": len(backend.siem.triggered_alerts),
                        "siem_alerts": list(reversed(backend.siem.triggered_alerts[-12:])),
                        "soar_isolated_devices": backend.soar.isolated_devices,
                        "soar_blocked_ips": backend.soar.blocked_ips,
                        "soar_safe_mode_actuators": backend.soar.safe_mode_actuators,
                        "soar_pending_approvals": backend.soar.pending_human_approvals,
                        "ai_isolation_forest_metrics": backend.ai_metrics_cache,
                    },
                )
                return

            self._send_json(404, {"status": "NOT_FOUND"})

        def log_message(self, format, *args):
            return

    return VilaAuroraRequestHandler


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Servidor Web e API Segura - Rede Comunitaria Vila Aurora")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    app_backend = VilaAuroraApplicationBackend()
    server = HTTPServer((args.host, args.port), create_http_handler(app_backend))
    print(f"[+] Painel de Supervisao Vila Aurora ativo em http://{args.host}:{args.port}")
    server.serve_forever()
