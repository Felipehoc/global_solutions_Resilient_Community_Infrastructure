"""
Simulador de Dispositivos de Campo IoT nos 5 Espaços Comunitários (RT-01)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Espaços Monitorados:
1. Unidade Básica de Saúde (UBS): Câmara fria de vacinas (2°C a 8°C), bateria, controle de acesso RFID
2. Escola Municipal: Nível do reservatório de água, bomba de recalque, cloro residual e turbidez
3. Abrigo de Emergência (Defesa Civil): Sensor de alagamento, qualidade do ar/umidade, gerador, fechadura
4. Centro Comunitário: Painéis solares fotovoltaicos, banco de baterias, crachá QR/RFID
5. Horta e Cozinha Solidária: Câmara fria de alimentos, umidade do solo, irrigação
"""

import uuid
import random
from datetime import datetime, timezone
from typing import Dict, Any, List


class VilaAuroraFieldSimulator:
    """Gera telemetria sintética realista e eventos de atuadores para os 5 espaços comunitários."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_telemetry_batch(self, inject_anomalies: bool = False) -> List[Dict[str, Any]]:
        """Gera um ciclo completo de leituras dos 5 espaços comunitários."""
        now_iso = datetime.now(timezone.utc).isoformat()
        readings = [
            # 1. UBS - Câmara Fria de Vacinas
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "UBS",
                "device_id": "ubs-camara-fria-01",
                "metric": "vaccine_temp_celsius",
                "value": round(self.rng.uniform(3.2, 6.4), 2) if not inject_anomalies else 13.8,
                "unit": "C",
                "safe_min": 2.0,
                "safe_max": 8.0,
            },
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "UBS",
                "device_id": "ubs-energia-bateria-01",
                "metric": "battery_soc_percent",
                "value": round(self.rng.uniform(82.0, 98.0), 1),
                "unit": "%",
                "safe_min": 30.0,
                "safe_max": 100.0,
            },
            # 2. Escola Municipal - Água e Bomba
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Escola_Municipal",
                "device_id": "escola-reservatorio-01",
                "metric": "water_level_percent",
                "value": round(self.rng.uniform(55.0, 88.0), 1) if not inject_anomalies else 8.5,
                "unit": "%",
                "safe_min": 20.0,
                "safe_max": 98.0,
            },
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Escola_Municipal",
                "device_id": "escola-qualidade-agua-01",
                "metric": "residual_chlorine_mg_l",
                "value": round(self.rng.uniform(0.6, 1.5), 2),
                "unit": "mg/L",
                "safe_min": 0.2,
                "safe_max": 2.0,
            },
            # 3. Abrigo de Emergência - Alagamento e Qualidade do Ar
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Abrigo_Emergencia",
                "device_id": "abrigo-alagamento-01",
                "metric": "flood_water_column_cm",
                "value": round(self.rng.uniform(0.0, 1.2), 2) if not inject_anomalies else 18.5,
                "unit": "cm",
                "safe_min": 0.0,
                "safe_max": 5.0,
            },
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Abrigo_Emergencia",
                "device_id": "abrigo-qualidade-ar-01",
                "metric": "co2_ppm",
                "value": round(self.rng.uniform(410.0, 680.0), 0),
                "unit": "ppm",
                "safe_min": 350.0,
                "safe_max": 1000.0,
            },
            # 4. Centro Comunitário - Energia Fotovoltaica
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Centro_Comunitario",
                "device_id": "centro-painel-solar-01",
                "metric": "solar_generation_kw",
                "value": round(self.rng.uniform(2.1, 5.8), 2),
                "unit": "kW",
                "safe_min": 0.0,
                "safe_max": 10.0,
            },
            # 5. Horta e Cozinha Solidária - Câmara Fria de Alimentos
            {
                "event_id": str(uuid.uuid4()),
                "timestamp_ntp": now_iso,
                "space": "Horta_Cozinha",
                "device_id": "horta-camara-fria-01",
                "metric": "food_cold_room_celsius",
                "value": round(self.rng.uniform(1.5, 4.8), 2),
                "unit": "C",
                "safe_min": 0.0,
                "safe_max": 6.0,
            },
        ]
        return readings


if __name__ == "__main__":
    import json

    sim = VilaAuroraFieldSimulator()
    print(json.dumps(sim.generate_telemetry_batch(), indent=2, ensure_ascii=False))

