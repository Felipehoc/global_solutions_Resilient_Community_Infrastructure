"""
Reprodução Controlada do Incidente INC-VA-0712 e Aquisição Forense Digital (RT-14 e Rubrica C5)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Fluxo Executado:
1. Reproduz em laboratório as 6 etapas do incidente INC-VA-0712 com relógios sincronizados via NTP.
2. Coleta os artefatos de evidência brutos em `forensics/evidence/`.
3. Calcula o hash criptográfico SHA-256 de cada evidência no exato momento da coleta.
4. Gera o Registro Formal de Cadeia de Custódia (`forensics/cadeia_de_custodia.json`).
5. Constrói a Linha do Tempo Consolidada e o Mapeamento completo no MITRE ATT&CK.
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.pki.pki_manager import VilaAuroraPKIManager
from src.backend.app import VilaAuroraApplicationBackend
from src.siem_soar.siem_engine import CentralizedSIEMEngine
from src.siem_soar.soar_playbook import SOARPlaybookOrchestrator


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def reproduce_incident_and_collect_forensics() -> Dict[str, Any]:
    evidence_dir = os.path.join("forensics", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)

    pki = VilaAuroraPKIManager()
    pki.provision_all_community_devices()
    backend = VilaAuroraApplicationBackend()
    siem = CentralizedSIEMEngine(
        log_file_path=os.path.join(evidence_dir, "EVD-01_central_siem_logs.jsonl"),
        alerts_file_path=os.path.join(evidence_dir, "EVD-02_siem_triggered_alerts.jsonl"),
    )
    soar = SOARPlaybookOrchestrator(pki_manager=pki, auth_manager=backend.auth)

    # Limpa arquivos de evidência anteriores para garantir reprodutibilidade determinística do hash
    for fn in ("EVD-01_central_siem_logs.jsonl", "EVD-02_siem_triggered_alerts.jsonl"):
        p = os.path.join(evidence_dir, fn)
        if os.path.exists(p):
            os.remove(p)

    # -------------------------------------------------------------------------
    # Reprodução Cronológica do Incidente INC-VA-0712 (Sincronizada via NTP)
    # -------------------------------------------------------------------------
    timeline_events = [
        {
            "timestamp_ntp": "2026-10-25T21:42:10Z",
            "component": "email_gateway",
            "event_type": "phishing_ai_voice_clone_received",
            "src_ip": "203.0.113.45",
            "user": "coordenacao03",
            "payload": "E-mail falso gerado por IA simulando Prefeitura + Audio WhatsApp com voz clonada solicitando recadastramento urgente.",
            "mitre_technique": "T1566.002 - Phishing: Spearphishing Link / AML.T0054 - AI Deepfake Social Engineering",
        },
        {
            "timestamp_ntp": "2026-10-25T21:48:55Z",
            "component": "phishing_landing_page",
            "event_type": "credential_harvested_no_mfa",
            "src_ip": "203.0.113.45",
            "user": "coordenacao03",
            "payload": "Coordenadora digitou usuario e senha na pagina falsa; VPN legada nao exigia segundo fator (MFA).",
            "mitre_technique": "T1598.003 - Phishing for Information: Spearphishing Link",
        },
        {
            "timestamp_ntp": "2026-10-26T02:14:03Z",
            "component": "vpn_gateway",
            "event_type": "vpn_login_anomaly",
            "src_ip": "198.51.100.99",
            "user": "coordenacao03",
            "payload": "Login VPN na madrugada (02h14) a partir de IP externo desconhecido (198.51.100.99) usando credencial roubada sem MFA.",
            "mitre_technique": "T1078 - Valid Accounts / T1133 - External Remote Services",
        },
        {
            "timestamp_ntp": "2026-10-26T02:17:29Z",
            "component": "web_panel",
            "event_type": "sql_injection_exploited",
            "src_ip": "198.51.100.99",
            "user": "coordenacao03",
            "endpoint": "/legacy/access-logs/search",
            "payload": "xyz%' UNION SELECT user_id, username, role, password_hash, space_assigned FROM operators_credentials --",
            "mitre_technique": "T1190 - Exploit Public-Facing Application / T1005 - Data from Local System",
        },
        {
            "timestamp_ntp": "2026-10-26T02:19:44Z",
            "component": "edge_controller",
            "event_type": "actuator_command_anomaly",
            "src_ip": "198.51.100.99",
            "user": "coordenacao03",
            "actuator_id": "escola-bomba-recalque-01",
            "payload": "Alteracao maliciosa do agendamento da bomba de agua da Escola para drenagem continua durante a madrugada.",
            "mitre_technique": "T1565.001 - Stored Data Manipulation / T0855 - Unauthorized Command Message",
        },
        {
            "timestamp_ntp": "2026-10-26T02:22:15Z",
            "component": "mosquitto_edge",
            "event_type": "cert_revoked_crl",
            "src_ip": "172.28.10.99",
            "device_id": "sensor-comprometido-99",
            "payload": "Tentativa de conexao MQTT por dispositivo não autorizado / certificado revogado para mascarar telemetria.",
            "mitre_technique": "T1552.004 - Unsecured Credentials: Private Keys / T1200 - Hardware Additions",
        },
        {
            "timestamp_ntp": "2026-10-26T03:05:00Z",
            "component": "edge_controller",
            "event_type": "wan_outage_local_cold_chain_protection",
            "src_ip": "127.0.0.1",
            "device_id": "ubs-camara-fria-01",
            "payload": "Queda do link de fibra durante temporal; temperatura da camara fria da UBS subiu para 11.4 C. Na nova arquitetura, a Borda Autonoma disparou sirene local e ligou compressor reserva imediatamente.",
            "mitre_technique": "T1498 - Network Denial of Service (Mitigated by Edge Autonomy RT-02)",
        },
    ]

    for ev in timeline_events:
        siem.ingest_log(ev, soar_orchestrator=soar)

    # Grava artefato EVD-03: Dump da exploração SQLi no legado vs bloqueio no novo
    sqli_dump = backend.search_access_logs_vulnerable_legacy(
        "xyz%' UNION SELECT user_id, username, role, password_hash, space_assigned FROM operators_credentials --"
    )
    evd03_path = os.path.join(evidence_dir, "EVD-03_sqli_forensic_artifact.json")
    with open(evd03_path, "w", encoding="utf-8") as f:
        json.dump(sqli_dump, f, indent=2, ensure_ascii=False)

    # Grava artefato EVD-04: Ações automatizadas SOAR e fila de aprovação humana
    evd04_path = os.path.join(evidence_dir, "EVD-04_soar_response_and_human_queue.json")
    with open(evd04_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "isolated_devices": soar.isolated_devices,
                "blocked_ips": soar.blocked_ips,
                "terminated_vpn_sessions": soar.terminated_vpn_sessions,
                "safe_mode_actuators": soar.safe_mode_actuators,
                "automated_actions_log": soar.automated_actions_log,
                "pending_human_approvals": soar.pending_human_approvals,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    # -------------------------------------------------------------------------
    # Cálculo imediato de Hashes SHA-256 e Registro de Cadeia de Custódia (RT-14)
    # -------------------------------------------------------------------------
    collection_time = datetime.now(timezone.utc).isoformat()
    evidence_files = [
        ("EVD-01", "EVD-01_central_siem_logs.jsonl", "Logs centralizados NTP contendo toda a sequencia do incidente INC-VA-0712"),
        ("EVD-02", "EVD-02_siem_triggered_alerts.jsonl", "Alertas gerados pelas 4 regras de deteccao (RT-13a, RT-13b, RT-13c, RT-13d)"),
        ("EVD-03", "EVD-03_sqli_forensic_artifact.json", "Artefato de bancada demonstrando a query injetada no sistema legado"),
        ("EVD-04", "EVD-04_soar_response_and_human_queue.json", "Registro de contencao automatica SOAR e retencao humana de alto impacto"),
    ]

    custody_items: List[Dict[str, Any]] = []
    for evd_id, filename, desc in evidence_files:
        full_path = os.path.join(evidence_dir, filename)
        digest = sha256_file(full_path)
        size_bytes = os.path.getsize(full_path)
        custody_items.append(
            {
                "evidence_id": evd_id,
                "filename": filename,
                "description": desc,
                "sha256_hash": digest,
                "size_bytes": size_bytes,
                "collected_at_ntp_utc": collection_time,
                "collected_by": "Perito_Forense_Digital_Equipe_FIAP (ID Sintetico: AUDITOR-04)",
                "collection_location": "Laboratorio Isolado Docker - Rede Vila Aurora (Host SIEM Central)",
                "collection_method": "Aquisicao logica imutavel com calculo imediato de hash SHA-256 (ISO/IEC 27037)",
                "storage_status": "LACRADO_READ_ONLY_VERIFICADO",
            }
        )

    custody_manifest = {
        "case_id": "INC-VA-0712",
        "standard_reference": "ABNT NBR ISO/IEC 27037:2013 & NIST SP 800-86",
        "ntp_stratum1_source": "a.st1.ntp.br",
        "chain_of_custody_records": custody_items,
        "timeline_reconstructed": timeline_events,
        "triggered_siem_alerts": siem.triggered_alerts,
    }

    custody_path = os.path.join("forensics", "cadeia_de_custodia.json")
    with open(custody_path, "w", encoding="utf-8") as f:
        json.dump(custody_manifest, f, indent=2, ensure_ascii=False)

    return custody_manifest


if __name__ == "__main__":
    print(json.dumps(reproduce_incident_and_collect_forensics(), indent=2, ensure_ascii=False))
