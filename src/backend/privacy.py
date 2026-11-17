"""
Módulo de Privacidade desde a Concepção - LGPD (RT-19)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Garante:
- Uso exclusivo de dados 100% sintéticos (nenhum dado pessoal real).
- Minimização de dados (coleta apenas do estritamente necessário para segurança física e auditoria).
- Pseudonimização criptográfica (HMAC-SHA256 com Salt dedicado) dos identificadores de crachá/voluntários
  nos registros de acesso físico e de sistema.
- Política de retenção automatizada e base legal documentada (Art. 7º, II e IX da LGPD).
"""

import os
import hmac
import hashlib
from typing import Dict, Any, List


class LGPDPrivacyManager:
    """Implementa pseudonimização, mascaramento e verificação de conformidade LGPD (RT-19)."""

    SYNTHETIC_VOLUNTEERS = [
        {
            "synthetic_id": "VOL-SINT-001",
            "display_label": "Voluntario_Operador_01 (Sintetico)",
            "role": "operador",
            "space_assigned": "Escola_Municipal",
            "badge_rfid_raw": "RFID-VA-9001-SINT",
            "email_synthetic": "operador01.sintetico@vilaaurora.org.br",
        },
        {
            "synthetic_id": "VOL-SINT-002",
            "display_label": "Tecnico_Manutencao_02 (Sintetico)",
            "role": "tecnico",
            "space_assigned": "UBS",
            "badge_rfid_raw": "RFID-VA-9002-SINT",
            "email_synthetic": "tecnico02.sintetico@vilaaurora.org.br",
        },
        {
            "synthetic_id": "VOL-SINT-003",
            "display_label": "Coordenadora_Comunitaria_03 (Sintetico)",
            "role": "coordenacao",
            "space_assigned": "Centro_Comunitario",
            "badge_rfid_raw": "RFID-VA-9003-SINT",
            "email_synthetic": "coordenacao03.sintetico@vilaaurora.org.br",
        },
        {
            "synthetic_id": "VOL-SINT-004",
            "display_label": "Auditor_Externo_04 (Sintetico)",
            "role": "auditor",
            "space_assigned": "Abrigo_Emergencia",
            "badge_rfid_raw": "RFID-VA-9004-SINT",
            "email_synthetic": "auditor04.sintetico@vilaaurora.org.br",
        },
        {
            "synthetic_id": "VOL-SINT-005",
            "display_label": "Voluntario_Horta_05 (Sintetico)",
            "role": "operador",
            "space_assigned": "Horta_Cozinha",
            "badge_rfid_raw": "RFID-VA-9005-SINT",
            "email_synthetic": "horta05.sintetico@vilaaurora.org.br",
        },
    ]

    def __init__(self, salt: str = None):
        self.salt = (salt or os.getenv("LGPD_PSEUDONYM_SALT", "vila_aurora_synthetic_salt_2026_lab")).encode("utf-8")

    def pseudonymize_identifier(self, raw_identifier: str) -> str:
        """Gera um pseudônimo irreversível sem a chave de salt (HMAC-SHA256 truncado)."""
        digest = hmac.new(self.salt, raw_identifier.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"PSEUDO-{digest[:16].upper()}"

    def sanitize_access_log_record(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove qualquer identificador direto (nome, crachá bruto, e-mail) antes de persistir no log,
        substituindo pelo token pseudonimizado (RT-19).
        """
        badge_or_user = raw_record.get("badge_rfid_raw") or raw_record.get("user_id") or "UNKNOWN"
        return {
            "log_id": raw_record.get("log_id"),
            "timestamp_ntp": raw_record.get("timestamp_ntp"),
            "pseudonym_token": self.pseudonymize_identifier(badge_or_user),
            "role_profile": raw_record.get("role", "operador"),
            "space": raw_record.get("space", "Centro_Comunitario"),
            "door_or_resource": raw_record.get("door_or_resource", "porta-principal"),
            "event_result": raw_record.get("event_result", "GRANTED"),
            "lgpd_synthetic_flag": True,
        }
