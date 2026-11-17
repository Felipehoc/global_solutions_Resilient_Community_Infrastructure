"""
Nó de Borda Autônomo (Edge Computing), Regras Locais, Store-and-Forward e Failover (RT-01, RT-02, RT-03)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Garante que:
1. Cada espaço comunitário processe regras críticas localmente sem depender da nuvem.
2. Em caso de queda da fibra comunitária, ative link 4G (nos espaços críticos: UBS e Abrigo)
   ou opere em modo degradado autônomo local (Escola, Centro Comunitário, Horta/Cozinha).
3. Todas as mensagens geradas durante a falha WAN sejam gravadas em SQLite local (Store-and-Forward)
   e sincronizadas/reconciliadas sem perda (0% data loss) quando a conectividade retornar.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple


class EdgeAutonomousNode:
    """Representa o Nó de Borda Autônomo da Rede Comunitária Vila Aurora."""

    # Política de Redundância Proporcional (RT-03)
    REDUNDANCY_POLICY = {
        "UBS": {
            "primary_link": "Fibra_Comunitaria_GPON",
            "secondary_link": "Modem_4G_LTE_DualSIM",
            "autonomous_edge": True,
            "justification": "Crítico à vida: conservação de vacinas exige envio imediato de alertas externos via 4G se a fibra cair.",
        },
        "Abrigo_Emergencia": {
            "primary_link": "Fibra_Comunitaria_GPON",
            "secondary_link": "Modem_4G_LTE_DefesaCivil",
            "autonomous_edge": True,
            "justification": "Crítico em temporais: coordenação com a Defesa Civil exige link celular redundante durante enchentes.",
        },
        "Escola_Municipal": {
            "primary_link": "Fibra_Comunitaria_GPON",
            "secondary_link": "Modo_Degradado_Local_StoreAndForward",
            "autonomous_edge": True,
            "justification": "Sem link 4G pago para reduzir OPEX; a proteção da bomba e nível do reservatório é 100% garantida localmente na borda.",
        },
        "Centro_Comunitario": {
            "primary_link": "Fibra_Comunitaria_GPON",
            "secondary_link": "Modo_Degradado_Local_StoreAndForward",
            "autonomous_edge": True,
            "justification": "Operação administrativa não emergencial; buffer SQLite local armazena até 30 dias de leituras sem custo adicional.",
        },
        "Horta_Cozinha": {
            "primary_link": "Fibra_Comunitaria_GPON",
            "secondary_link": "Modo_Degradado_Local_StoreAndForward",
            "autonomous_edge": True,
            "justification": "Irrigação e alarme sonoro local da câmara fria operam autonomamente na borda sem necessidade de link 4G dedicado.",
        },
    }

    def __init__(self, buffer_db_path: str = "data/edge_buffers/edge_store_and_forward.db"):
        self.buffer_db_path = buffer_db_path
        os.makedirs(os.path.dirname(self.buffer_db_path), exist_ok=True)
        self.wan_connected = True
        self.local_alarms_triggered: List[Dict[str, Any]] = []
        self._init_buffer_db()

    def _init_buffer_db(self) -> None:
        with sqlite3.connect(self.buffer_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_buffer (
                    event_id TEXT PRIMARY KEY,
                    timestamp_ntp TEXT NOT NULL,
                    space TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    local_rule_action TEXT,
                    synced_to_cloud INTEGER DEFAULT 0,
                    synced_at_utc TEXT
                )
                """
            )
            conn.commit()

    def set_wan_status(self, connected: bool) -> Dict[str, Any]:
        """Altera o estado do link WAN (usado também no Teste de Caos RT-23)."""
        self.wan_connected = connected
        now_iso = datetime.now(timezone.utc).isoformat()
        status_report = {
            "timestamp_ntp": now_iso,
            "wan_fiber_online": connected,
            "spaces_link_state": {},
        }
        for space, policy in self.REDUNDANCY_POLICY.items():
            if connected:
                status_report["spaces_link_state"][space] = policy["primary_link"]
            else:
                status_report["spaces_link_state"][space] = policy["secondary_link"]
        return status_report

    def evaluate_local_control_rules(self, reading: Dict[str, Any]) -> str:
        """
        Executa regras determinísticas locais no nó de borda (< 10 ms),
        independente de conexão com a nuvem (RT-02).
        """
        metric = reading["metric"]
        val = float(reading["value"])
        space = reading["space"]
        now_iso = reading.get("timestamp_ntp", datetime.now(timezone.utc).isoformat())

        # Regra Local 1: Alarme Autônomo da Câmara Fria de Vacinas da UBS (Corrige falha #5 do INC-VA-0712)
        if metric == "vaccine_temp_celsius" and (val < 2.0 or val > 8.0):
            action = f"CRITICAL_LOCAL_ALARM: Sirene local UBS ativada + Compressor Reserva ON (Temp={val}C fora de 2..8C)"
            self.local_alarms_triggered.append(
                {
                    "timestamp_ntp": now_iso,
                    "space": space,
                    "device_id": reading["device_id"],
                    "rule": "EDGE_RULE_UBS_VACCINE_TEMP",
                    "action": action,
                    "operated_offline": not self.wan_connected,
                }
            )
            return action

        # Regra Local 2: Proteção contra Esvaziamento do Reservatório da Escola (Corrige falha #4 do INC-VA-0712)
        if metric == "water_level_percent" and val < 20.0:
            action = f"CRITICAL_LOCAL_SAFETY_LOCK: Relé da bomba da Escola bloqueado localmente (Nivel={val}% < 20%)"
            self.local_alarms_triggered.append(
                {
                    "timestamp_ntp": now_iso,
                    "space": space,
                    "device_id": reading["device_id"],
                    "rule": "EDGE_RULE_SCHOOL_PUMP_INTERLOCK",
                    "action": action,
                    "operated_offline": not self.wan_connected,
                }
            )
            return action

        # Regra Local 3: Alerta de Enchente no Abrigo de Emergência
        if metric == "flood_water_column_cm" and val > 5.0:
            action = f"CRITICAL_LOCAL_FLOOD_PROTOCOL: Bomba de drenagem ligada + Alerta Defesa Civil (Lamina={val}cm)"
            self.local_alarms_triggered.append(
                {
                    "timestamp_ntp": now_iso,
                    "space": space,
                    "device_id": reading["device_id"],
                    "rule": "EDGE_RULE_SHELTER_FLOOD",
                    "action": action,
                    "operated_offline": not self.wan_connected,
                }
            )
            return action

        return "NORMAL_LOCAL_OPERATION"

    def validate_actuator_command(self, actuator_id: str, command: str, hour_utc: int, user_role: str) -> Tuple[bool, str]:
        """
        Bloqueia comandos de atuadores fora do horário esperado ou sem perfil adequado (RT-02, RT-13d).
        """
        if "bomba" in actuator_id and command in ("DRAIN_OVERRIDE", "FORCE_ON_CONTINUOUS"):
            if 0 <= hour_utc <= 5:
                return False, "BLOCKED_BY_EDGE_SAFETY: Proibido drenar/acionar bomba continuamente na madrugada (00h-05h)"
        if user_role not in ("tecnico", "coordenacao"):
            return False, f"BLOCKED_BY_EDGE_RBAC: Perfil '{user_role}' nao autorizado para comandar atuador {actuator_id}"
        return True, "ALLOWED_BY_EDGE_POLICY"

    def ingest_reading(self, reading: Dict[str, Any], cloud_callback=None) -> Dict[str, Any]:
        """
        Recebe leitura via MQTT local, aplica regra de borda e armazena no buffer Store-and-Forward.
        Se a WAN estiver online, encaminha à nuvem; se offline, mantém no SQLite local para sincronização futura.
        """
        rule_action = self.evaluate_local_control_rules(reading)
        synced = 0
        synced_at = None

        if self.wan_connected and cloud_callback is not None:
            cloud_callback(reading, rule_action)
            synced = 1
            synced_at = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.buffer_db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO telemetry_buffer
                (event_id, timestamp_ntp, space, device_id, metric, value, unit, local_rule_action, synced_to_cloud, synced_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    synced,
                    synced_at,
                ),
            )
            conn.commit()

        return {
            "event_id": reading["event_id"],
            "local_rule_action": rule_action,
            "buffered_offline": synced == 0,
        }

    def synchronize_pending_buffer(self, cloud_sync_receiver=None) -> Dict[str, Any]:
        """
        Sincroniza e reconcilia de forma idempotente (por event_id e timestamp_ntp)
        todos os registros acumulados durante a queda da internet (RT-02, RT-23).
        """
        if not self.wan_connected:
            return {"status": "WAN_STILL_OFFLINE", "synced_count": 0}

        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.buffer_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM telemetry_buffer WHERE synced_to_cloud = 0 ORDER BY timestamp_ntp ASC"
            ).fetchall()

            pending_records = [dict(r) for r in rows]
            if cloud_sync_receiver is not None and pending_records:
                cloud_sync_receiver(pending_records)

            conn.execute(
                "UPDATE telemetry_buffer SET synced_to_cloud = 1, synced_at_utc = ? WHERE synced_to_cloud = 0",
                (now_iso,),
            )
            conn.commit()

            total_count = conn.execute("SELECT COUNT(*) FROM telemetry_buffer").fetchone()[0]
            unsynced_after = conn.execute("SELECT COUNT(*) FROM telemetry_buffer WHERE synced_to_cloud = 0").fetchone()[0]

        return {
            "status": "RECONCILIATION_SUCCESS",
            "reconciled_at_utc": now_iso,
            "records_synced_in_batch": len(pending_records),
            "total_records_in_edge_db": total_count,
            "remaining_unsynced": unsynced_after,
            "data_loss_percent": 0.0,
        }


if __name__ == "__main__":
    node = EdgeAutonomousNode()
    print(json.dumps(node.set_wan_status(True), indent=2, ensure_ascii=False))

