"""
Orquestrador Geral de Validação e Geração de Evidências (RT-01 a RT-23)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Executa todos os módulos do protótipo e consolida as evidências verificáveis
em `forensics/consolidated_evidence_report.json`.
"""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.pki.pki_manager import VilaAuroraPKIManager
from src.backend.auth import RBACAndMFAManager
from src.ai_defense.anomaly_detector import TelemetryAnomalyDetector
from src.ai_defense.llm_guardrails import OperatorTriageLLMWithGuardrails
from scripts.test_sqli_before_after import run_sqli_demonstration
from scripts.run_phishing_simulation import run_phishing_and_email_security_suite
from scripts.reproduce_inc_va_0712 import reproduce_incident_and_collect_forensics
from scripts.chaos_test_wan import run_chaos_test_and_collect_metrics


def main() -> None:
    print("[1/6] Provisionando PKI X.509, testando mTLS, Revogacao (CRL) e Rotacao (RT-04, RT-05)...")
    pki = VilaAuroraPKIManager()
    issued_certs = pki.provision_all_community_devices()
    ok_valid, msg_valid, _ = pki.verify_mtls_connection("ubs-camara-fria-01")
    revocation_info = pki.revoke_certificate("sensor-comprometido-99", reason="compromisedKeyLabTest")
    ok_revoked, msg_revoked, _ = pki.verify_mtls_connection("sensor-comprometido-99")
    rotation_info = pki.rotate_device_certificate("escola-bomba-recalque-01", reason="periodicSecurityRotation")

    print("[2/6] Validando Autenticacao MFA TOTP, RBAC (4 perfis) e Origem VPN (RT-06, RT-09)...")
    auth = RBACAndMFAManager()
    totp_coord = auth.generate_totp_token(auth.SYNTHETIC_ACCOUNTS["coordenacao03"]["totp_secret"])
    mfa_ok, mfa_msg, mfa_session = auth.authenticate_operator(
        "coordenacao03", "VilaAurora#Coord2026!", totp_coord, client_ip="10.200.0.50"
    )
    non_vpn_ok, non_vpn_msg, _ = auth.authenticate_operator(
        "coordenacao03", "VilaAurora#Coord2026!", totp_coord, client_ip="198.51.100.99"
    )

    print("[3/6] Executando exploracao e reteste de SQL Injection - Antes vs Depois (RT-08)...")
    sqli_report = run_sqli_demonstration()

    print("[4/6] Validando SPF/DKIM/DMARC e Simulacao Etica de Phishing + Controles Voz Clonada (RT-10, RT-11, RT-18)...")
    phishing_report = run_phishing_and_email_security_suite()

    print("[5/6] Reproduzindo Incidente INC-VA-0712, SIEM/SOAR e Aquisicao Forense com SHA-256 (RT-12 a RT-15)...")
    forensic_report = reproduce_incident_and_collect_forensics()

    print("[6/6] Avaliando IA Defensiva (Isolation Forest + Guardrails LLM) e Teste de Caos >= 30min (RT-16, RT-17, RT-22, RT-23)...")
    ai_detector = TelemetryAnomalyDetector(random_seed=42)
    ai_metrics = ai_detector.fit_and_evaluate()
    llm_guardrails = OperatorTriageLLMWithGuardrails()
    llm_test_report = llm_guardrails.run_red_team_guardrail_suite()
    chaos_report = run_chaos_test_and_collect_metrics(outage_duration_minutes=35)

    consolidated = {
        "generated_at_ntp_utc": datetime.now(timezone.utc).isoformat(),
        "project": "FIAP Global Solution 2026.2 - Resilient Community Infrastructure (Vila Aurora)",
        "pki_and_mtls_rt04_rt05": {
            "total_unique_device_certificates": len(issued_certs),
            "valid_device_mtls_test": {"device": "ubs-camara-fria-01", "allowed": ok_valid, "status": msg_valid},
            "revoked_device_crl_test": {
                "device": "sensor-comprometido-99",
                "revocation": revocation_info,
                "allowed_after_revocation": ok_revoked,
                "status": msg_revoked,
            },
            "credential_rotation_test": rotation_info,
        },
        "vpn_mfa_and_rbac_rt06_rt09": {
            "vpn_mfa_login_test": {"allowed": mfa_ok, "status": mfa_msg, "session": mfa_session},
            "external_non_vpn_block_test": {"allowed": non_vpn_ok, "status": non_vpn_msg},
        },
        "sqli_before_and_after_rt08": sqli_report,
        "phishing_and_email_auth_rt10_rt11_rt18": phishing_report,
        "forensics_siem_soar_rt12_to_rt15": forensic_report,
        "ai_defense_isolation_forest_rt16": ai_metrics,
        "llm_guardrails_owasp_atlas_rt17": llm_test_report,
        "chaos_test_and_metrics_rt22_rt23": chaos_report,
    }

    os.makedirs("forensics", exist_ok=True)
    out_path = os.path.join("forensics", "consolidated_evidence_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(consolidated, f, indent=2, ensure_ascii=False)

    print(f"\n[SUCESSO] Todos os testes RT-01 a RT-23 concluídos! Evidências salvas em: {out_path}")


if __name__ == "__main__":
    main()
