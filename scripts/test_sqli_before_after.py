"""
Script de Demonstração e Reteste de SQL Injection - Antes vs Depois (RT-08 e Rubrica C3)
Rede Comunitária Vila Aurora - Global Solution 2026.2
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.backend.app import VilaAuroraApplicationBackend


def run_sqli_demonstration() -> dict:
    backend = VilaAuroraApplicationBackend()

    # Payload 1: Extração da tabela de usuários via UNION SELECT (Incidente INC-VA-0712 etapa 3/4)
    sqli_union_payload = "xyz%' UNION SELECT user_id, username, role, password_hash, space_assigned FROM operators_credentials --"

    # Payload 2: Bypass booleano clássico
    sqli_boolean_payload = "' OR '1'='1"

    # 1. Demonstração do ANTES (Painel Legado Vulnerável)
    before_union_result = backend.search_access_logs_vulnerable_legacy(sqli_union_payload)
    before_boolean_result = backend.search_access_logs_vulnerable_legacy(sqli_boolean_payload)

    # 2. Demonstração do DEPOIS (Painel Corrigido: WAF + Validação + Query Parametrizada + Menor Privilégio)
    after_union_status, after_union_result = backend.search_access_logs_secure(sqli_union_payload)
    after_boolean_status, after_boolean_result = backend.search_access_logs_secure(sqli_boolean_payload)
    after_legit_status, after_legit_result = backend.search_access_logs_secure("UBS")

    return {
        "requirement": "RT-08",
        "before_vulnerable_legacy": {
            "union_select_attack_payload": sqli_union_payload,
            "union_select_leaked_records_count": before_union_result.get("records_returned", 0),
            "union_select_sample_leaked_row": (before_union_result.get("data") or [None])[0],
            "boolean_bypass_payload": sqli_boolean_payload,
            "boolean_bypass_records_count": before_boolean_result.get("records_returned", 0),
        },
        "after_remediated_secure": {
            "root_cause_fixes": [
                "Prepared Statements / Parameterized Queries (?)",
                "Server-side Allowlist Regex Validation (^[a-zA-Z0-9_\\-\\s]{1,40}$)",
                "Database Least Privilege View (v_public_access_history without operators_credentials access)",
                "Generic Error Handling (zero stacktrace or schema leakage)",
                "WAF Inspection Layer blocking SQLi signatures and alerting SIEM (RT-13b)",
            ],
            "retest_union_select_http_status": after_union_status,
            "retest_union_select_response": after_union_result,
            "retest_boolean_bypass_http_status": after_boolean_status,
            "retest_boolean_bypass_response": after_boolean_result,
            "legitimate_query_http_status": after_legit_status,
            "legitimate_query_records_count": after_legit_result.get("records_returned", 0),
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_sqli_demonstration(), indent=2, ensure_ascii=False))
