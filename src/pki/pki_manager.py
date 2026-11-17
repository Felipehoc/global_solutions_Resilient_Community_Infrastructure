"""
Módulo PKI e Identidade de Dispositivos (RT-04 e RT-05)
Rede Comunitária Vila Aurora - Global Solution 2026.2

Responsabilidades:
- Emitir Autoridade Certificadora (CA) própria do projeto (VilaAurora-Root-CA)
- Emitir certificados X.509 únicos por dispositivo (proibido segredo compartilhado)
- Manter e exportar Lista de Revogação de Certificados (CRL) para bloqueio mTLS
- Demonstrar rotação automatizada de credenciais/certificados de dispositivos
"""

import os
import json
import uuid
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Tuple


class VilaAuroraPKIManager:
    """Gerenciador de PKI X.509, mTLS, Revogação (CRL) e Rotação de Credenciais."""

    DEVICES_CATALOG = [
        {"device_id": "ubs-camara-fria-01", "space": "UBS", "type": "sensor_temp_vacina"},
        {"device_id": "ubs-energia-bateria-01", "space": "UBS", "type": "sensor_energia"},
        {"device_id": "ubs-fechadura-rfid-01", "space": "UBS", "type": "controle_acesso"},
        {"device_id": "escola-reservatorio-01", "space": "Escola_Municipal", "type": "sensor_nivel_agua"},
        {"device_id": "escola-bomba-recalque-01", "space": "Escola_Municipal", "type": "atuador_bomba"},
        {"device_id": "escola-qualidade-agua-01", "space": "Escola_Municipal", "type": "sensor_cloro_turbidez"},
        {"device_id": "abrigo-alagamento-01", "space": "Abrigo_Emergencia", "type": "sensor_alagamento"},
        {"device_id": "abrigo-qualidade-ar-01", "space": "Abrigo_Emergencia", "type": "sensor_ar_umidade"},
        {"device_id": "abrigo-fechadura-01", "space": "Abrigo_Emergencia", "type": "atuador_porta"},
        {"device_id": "centro-painel-solar-01", "space": "Centro_Comunitario", "type": "sensor_fotovoltaico"},
        {"device_id": "horta-camara-fria-01", "space": "Horta_Cozinha", "type": "sensor_temp_alimentos"},
        {"device_id": "sensor-comprometido-99", "space": "Escola_Municipal", "type": "dispositivo_teste_revogacao"},
    ]

    def __init__(self, certs_dir: str = "certs"):
        self.certs_dir = certs_dir
        os.makedirs(self.certs_dir, exist_ok=True)
        self.registry_path = os.path.join(self.certs_dir, "pki_registry.json")
        self.crl_path = os.path.join(self.certs_dir, "crl.pem")
        self.ca_key_secret = self._load_or_create_ca()

    def _load_or_create_ca(self) -> str:
        ca_cert_path = os.path.join(self.certs_dir, "ca.crt")
        if os.path.exists(self.registry_path):
            with open(self.registry_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("ca_Internal_id", "vila-aurora-root-ca-2026")

        ca_id = f"CA-VA-{uuid.uuid4().hex[:12].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        ca_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            f"Subject: CN=VilaAurora-Root-CA, O=Rede Comunitaria Vila Aurora, L=Serra Clara, ST=SP, C=BR\n"
            f"SerialNumber: {ca_id}\n"
            f"NotBefore: {now_iso}\n"
            f"NotAfter: {(datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()}\n"
            f"SignatureAlgorithm: sha256WithRSAEncryption\n"
            f"Fingerprint-SHA256: {hashlib.sha256(ca_id.encode()).hexdigest()}\n"
            "-----END CERTIFICATE-----\n"
        )
        with open(ca_cert_path, "w", encoding="utf-8") as f:
            f.write(ca_pem)

        registry = {
            "ca_subject": "CN=VilaAurora-Root-CA, O=Rede Comunitaria Vila Aurora, C=BR",
            "ca_Internal_id": ca_id,
            "created_at_utc": now_iso,
            "certificates": {},
            "revoked_serials": {},
            "rotation_history": [],
        }
        with open(self.registry_path, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2, ensure_ascii=False)

        self._export_crl(registry)
        return ca_id

    def _load_registry(self) -> Dict[str, Any]:
        with open(self.registry_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_registry(self, registry: Dict[str, Any]) -> None:
        with open(self.registry_path, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2, ensure_ascii=False)
        self._export_crl(registry)

    def _export_crl(self, registry: Dict[str, Any]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        lines = [
            "-----BEGIN X509 CRL-----",
            f"Issuer: {registry['ca_subject']}",
            f"LastUpdate: {now_iso}",
            f"NextUpdate: {(datetime.now(timezone.utc) + timedelta(days=7)).isoformat()}",
            "RevokedCertificates:",
        ]
        for serial, info in registry.get("revoked_serials", {}).items():
            lines.append(f"  - Serial: {serial} | Device: {info['device_id']} | Date: {info['revoked_at']} | Reason: {info['reason']}")
        lines.append("-----END X509 CRL-----\n")
        with open(self.crl_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def issue_device_certificate(self, device_id: str, space: str, dev_type: str, validity_days: int = 365) -> Dict[str, Any]:
        """Emite um certificado X.509 individual para o dispositivo (RT-04)."""
        registry = self._load_registry()
        now = datetime.now(timezone.utc)
        serial = hashlib.sha256(f"{device_id}:{now.isoformat()}:{uuid.uuid4()}".encode()).hexdigest()[:20].upper()
        signature = hmac.new(self.ca_key_secret.encode(), f"{device_id}:{serial}:{space}".encode(), hashlib.sha256).hexdigest()

        cert_record = {
            "device_id": device_id,
            "common_name": f"{device_id}.iot.vilaaurora.org.br",
            "space": space,
            "device_type": dev_type,
            "serial_number": serial,
            "issuer": registry["ca_subject"],
            "not_before_utc": now.isoformat(),
            "not_after_utc": (now + timedelta(days=validity_days)).isoformat(),
            "fingerprint_sha256": signature,
            "status": "VALID",
            "key_algorithm": "ECDSA-P256 / RSA-2048",
        }

        cert_file = os.path.join(self.certs_dir, f"{device_id}.crt")
        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            f"Subject: CN={cert_record['common_name']}, OU={space}, O=Rede Comunitaria Vila Aurora\n"
            f"Issuer: {registry['ca_subject']}\n"
            f"SerialNumber: {serial}\n"
            f"NotBefore: {cert_record['not_before_utc']}\n"
            f"NotAfter: {cert_record['not_after_utc']}\n"
            f"PublicKeyAlgorithm: {cert_record['key_algorithm']}\n"
            f"CA-Signature-SHA256: {signature}\n"
            "-----END CERTIFICATE-----\n"
        )
        with open(cert_file, "w", encoding="utf-8") as f:
            f.write(cert_pem)

        registry["certificates"][device_id] = cert_record
        self._save_registry(registry)
        return cert_record

    def provision_all_community_devices(self) -> List[Dict[str, Any]]:
        """Provisiona certificados X.509 únicos para todos os dispositivos dos 5 espaços."""
        issued = []
        for dev in self.DEVICES_CATALOG:
            cert = self.issue_device_certificate(dev["device_id"], dev["space"], dev["type"])
            issued.append(cert)
        return issued

    def revoke_certificate(self, device_id: str, reason: str = "keyCompromise") -> Dict[str, Any]:
        """Revoga o certificado de um dispositivo comprometido e atualiza a CRL (RT-05)."""
        registry = self._load_registry()
        cert = registry["certificates"].get(device_id)
        if not cert:
            raise ValueError(f"Dispositivo {device_id} não possui certificado registrado.")

        serial = cert["serial_number"]
        now_iso = datetime.now(timezone.utc).isoformat()
        cert["status"] = "REVOKED"
        cert["revoked_at_utc"] = now_iso
        cert["revocation_reason"] = reason

        revocation_entry = {
            "device_id": device_id,
            "serial_number": serial,
            "revoked_at": now_iso,
            "reason": reason,
        }
        registry["revoked_serials"][serial] = revocation_entry
        self._save_registry(registry)
        return revocation_entry

    def rotate_device_certificate(self, device_id: str, reason: str = "scheduledRotation") -> Dict[str, Any]:
        """Revoga o certificado antigo e emite um novo com serial distinto (RT-05)."""
        registry = self._load_registry()
        old_cert = registry["certificates"].get(device_id)
        if not old_cert:
            raise ValueError(f"Dispositivo {device_id} não encontrado para rotação.")

        old_serial = old_cert["serial_number"]
        self.revoke_certificate(device_id, reason=reason)
        new_cert = self.issue_device_certificate(device_id, old_cert["space"], old_cert["device_type"])

        registry = self._load_registry()
        rotation_event = {
            "device_id": device_id,
            "old_serial": old_serial,
            "new_serial": new_cert["serial_number"],
            "rotated_at_utc": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }
        registry["rotation_history"].append(rotation_event)
        self._save_registry(registry)
        return rotation_event

    def verify_mtls_connection(self, device_id: str, presented_serial: str = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Simula o handshake mTLS do Broker Mosquitto / Backend com checagem de CRL (RT-04, RT-05, RT-13c).
        Retorna (aprovado, motivo, detalhes_evento).
        """
        registry = self._load_registry()
        now_iso = datetime.now(timezone.utc).isoformat()

        if not device_id or device_id not in registry["certificates"]:
            return (
                False,
                "CERT_MISSING_OR_UNKNOWN_CA",
                {
                    "timestamp_ntp": now_iso,
                    "component": "mosquitto_edge",
                    "event_type": "cert_missing",
                    "device_id": device_id or "anonymous",
                    "src_ip": "172.28.10.99",
                    "decision": "REJECTED_MTLS",
                },
            )

        cert = registry["certificates"][device_id]
        serial_to_check = presented_serial or cert["serial_number"]

        if serial_to_check in registry["revoked_serials"] or cert.get("status") == "REVOKED":
            return (
                False,
                "CERT_REVOKED_IN_CRL",
                {
                    "timestamp_ntp": now_iso,
                    "component": "mosquitto_edge",
                    "event_type": "cert_revoked_crl",
                    "device_id": device_id,
                    "serial_number": serial_to_check,
                    "src_ip": "172.28.10.99",
                    "decision": "REJECTED_CRL_BLOCK",
                },
            )

        if serial_to_check != cert["serial_number"]:
            return (
                False,
                "SERIAL_MISMATCH_OLD_CREDENTIAL",
                {
                    "timestamp_ntp": now_iso,
                    "component": "mosquitto_edge",
                    "event_type": "mtls_handshake_failed",
                    "device_id": device_id,
                    "serial_number": serial_to_check,
                    "src_ip": "172.28.10.99",
                    "decision": "REJECTED_SERIAL_MISMATCH",
                },
            )

        return (
            True,
            "MTLS_VERIFIED_OK",
            {
                "timestamp_ntp": now_iso,
                "component": "mosquitto_edge",
                "event_type": "mtls_authenticated",
                "device_id": device_id,
                "common_name": cert["common_name"],
                "serial_number": serial_to_check,
                "space": cert["space"],
                "decision": "ALLOWED",
            },
        )
