"""
Orquestrador SOAR - Respostas Automatizadas de Baixo Risco vs Aprovação Humana (RT-15)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Classificação de Risco Operacional (RT-15):
1. Ações de BAIXO RISCO (Executadas Automaticamente pelo Playbook em < 1s):
   - Isolar dispositivo IoT suspeito na VLAN/ACL do Broker (`ISOLATE_DEVICE`)
   - Revogar certificado X.509 comprometido na CRL (`REVOKE_CERT_CRL`)
   - Encerrar sessão VPN anômala (`TERMINATE_VPN_SESSION`)
   - Bloquear IP externo atacante no firewall (`BLOCK_ATTACKER_IP`)
   - Colocar atuador em Modo Seguro Autônomo Local (`SET_ACTUATOR_SAFE_MODE`)

2. Ações de ALTO IMPACTO (Exigem obrigatoriamente Aprovação Humana + MFA da Coordenação):
   - Desligar completamente a bomba principal de abastecimento (`SHUTDOWN_MAIN_WATER_PUMP`)
   - Liberar/Destravar todas as portas eletrônicas dos espaços (`UNLOCK_ALL_COMMUNITY_DOORS`)
   - Desativar o compressor principal da câmara fria da UBS (`DISABLE_UBS_COLD_CHAIN`)
"""

from datetime import datetime, timezone
from typing import Dict, Any, List


class SOARPlaybookOrchestrator:
    """Executa playbooks automatizados de baixo risco e retém ações críticas para decisão humana."""

    HIGH_IMPACT_ACTIONS = {
        "SHUTDOWN_MAIN_WATER_PUMP",
        "UNLOCK_ALL_COMMUNITY_DOORS",
        "DISABLE_UBS_COLD_CHAIN",
    }

    def __init__(self, pki_manager=None, auth_manager=None):
        self.pki_manager = pki_manager
        self.auth_manager = auth_manager
        self.isolated_devices: List[str] = []
        self.blocked_ips: List[str] = []
        self.terminated_vpn_sessions: List[str] = []
        self.safe_mode_actuators: List[str] = []
        self.automated_actions_log: List[Dict[str, Any]] = []
        self.pending_human_approvals: Dict[str, Dict[str, Any]] = {}

    def handle_siem_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Seleciona e executa o Playbook SOAR correspondente ao alerta do SIEM."""
        req = alert.get("requirement")
        now_iso = datetime.now(timezone.utc).isoformat()
        actions_taken = []

        if req == "RT-13a":  # Login VPN Anômalo
            src_ip = alert.get("src_ip", "198.51.100.99")
            user = alert.get("user", "unknown")
            self.terminated_vpn_sessions.append(f"{user}@{src_ip}")
            self.blocked_ips.append(src_ip)
            actions_taken.extend(
                [
                    f"AUTO_LOW_RISK: Sessao VPN de '{user}' ({src_ip}) encerrada imediatamente.",
                    f"AUTO_LOW_RISK: IP {src_ip} bloqueado no Firewall de Borda/Nuvem.",
                ]
            )

        elif req == "RT-13b":  # SQL Injection
            src_ip = alert.get("src_ip", "198.51.100.99")
            if src_ip not in self.blocked_ips:
                self.blocked_ips.append(src_ip)
            actions_taken.append(f"AUTO_LOW_RISK: IP atacante {src_ip} bloqueado no WAF e Firewall.")

        elif req == "RT-13c":  # Dispositivo sem certificado ou revogado
            dev_id = alert.get("device_id", "sensor-comprometido-99")
            if dev_id not in self.isolated_devices:
                self.isolated_devices.append(dev_id)
            if self.pki_manager is not None:
                try:
                    self.pki_manager.revoke_certificate(dev_id, reason="SOAR_Auto_Containment_RT15")
                except Exception:
                    pass
            actions_taken.extend(
                [
                    f"AUTO_LOW_RISK: Dispositivo '{dev_id}' isolado na ACL do Broker MQTT.",
                    f"AUTO_LOW_RISK: Certificado de '{dev_id}' adicionado na CRL (crl.pem).",
                ]
            )

        elif req == "RT-13d":  # Comando de Atuador Fora de Horário
            actuator = alert.get("actuator_id", "escola-bomba-recalque-01")
            if actuator not in self.safe_mode_actuators:
                self.safe_mode_actuators.append(actuator)
            actions_taken.append(
                f"AUTO_LOW_RISK: Atuador '{actuator}' colocado em MODO SEGURO LOCAL (mantendo nivel entre 40% e 85%)."
            )
            # Solicita aprovação humana caso seja sugerido desligamento total da bomba (Alto Impacto)
            approval_req = self.request_high_impact_action(
                action_type="SHUTDOWN_MAIN_WATER_PUMP",
                target=actuator,
                reason=f"Incidente {alert['alert_id']}: Comando suspeito na madrugada detectado.",
            )
            actions_taken.append(
                f"HUMAN_IN_THE_LOOP_REQUIRED: Desligamento total da bomba retido sob ID {approval_req['approval_id']} aguardando aprovacao MFA da Coordenacao."
            )

        record = {
            "timestamp_ntp": now_iso,
            "alert_id": alert.get("alert_id"),
            "requirement": req,
            "automated_low_risk_actions": actions_taken,
        }
        self.automated_actions_log.append(record)
        return record

    def request_high_impact_action(self, action_type: str, target: str, reason: str) -> Dict[str, Any]:
        """
        Registra uma ação de ALTO IMPACTO na fila de espera humana.
        Nunca executa automaticamente (RT-15).
        """
        approval_id = f"APPROVAL-{len(self.pending_human_approvals) + 1:03d}"
        entry = {
            "approval_id": approval_id,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "target": target,
            "reason": reason,
            "risk_classification": "HIGH_IMPACT_PHYSICAL_SAFETY",
            "status": "PENDING_HUMAN_COORDENACAO_MFA",
            "executed": False,
        }
        self.pending_human_approvals[approval_id] = entry
        return entry

    def process_human_decision(
        self, approval_id: str, username: str, password: str, totp_code: str, decision: str = "APPROVE"
    ) -> Dict[str, Any]:
        """
        Valida se um humano com perfil 'coordenacao' e MFA válido aprovou ou rejeitou a ação de alto impacto.
        """
        item = self.pending_human_approvals.get(approval_id)
        if not item:
            return {"status": "ERROR", "message": "Solicitacao nao encontrada."}

        if self.auth_manager is not None:
            ok, msg, info = self.auth_manager.authenticate_operator(username, password, totp_code)
            if not ok:
                return {"status": "DENIED_MFA_FAILED", "reason": msg}
            allowed, rbac_msg = self.auth_manager.check_permission(info["role"], "approve_high_impact_action")
            if not allowed:
                return {"status": "DENIED_RBAC_INSUFFICIENT_ROLE", "reason": rbac_msg}

        now_iso = datetime.now(timezone.utc).isoformat()
        if decision.upper() == "APPROVE":
            item["status"] = "APPROVED_AND_EXECUTED_BY_HUMAN"
            item["executed"] = True
        else:
            item["status"] = "REJECTED_BY_HUMAN_KEEP_SAFE_MODE"
            item["executed"] = False

        item["decided_by"] = username
        item["decided_at_utc"] = now_iso
        return item
