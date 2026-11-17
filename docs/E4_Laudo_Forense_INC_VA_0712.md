# E4 — Laudo Pericial Forense Digital: Incidente `INC-VA-0712`
**FIAP · Global Solution 2026.2 · Resilient Community Infrastructure · Turma: 4ECR**  
**Caso:** `INC-VA-0712` · **Organização:** Rede Comunitária Vila Aurora (Serra Clara - SP)  
**Professor:** Prof. Carlos Eduardo de Siqueira  
**Integrantes:** Felipe Henrique de Oliveira Cruz (RM 552566) · Octhor Festa (RM 552533)  
**Repositório Git (E2):** https://github.com/Felipehoc/global_solutions_Resilient_Community_Infrastructure  
**Referências Normativas:** ABNT NBR ISO/IEC 27037:2013 (Diretrizes para identificação, coleta, aquisição e preservação de evidência digital) e NIST SP 800-86.

---

## 1. Escopo e Objetivo da Perícia Forense (RT-14)

Este laudo técnico documenta a reprodução controlada em laboratório isolado e a investigação forense digital do incidente cibernético **INC-VA-0712**, ocorrido contra a infraestrutura da Rede Comunitária Vila Aurora. No incidente original, a ausência de sincronismo NTP e a sobrescrita de logs impediram a atribuição conclusiva dos fatos. Na nova arquitetura implementada (`scripts/reproduce_inc_va_0712.py`), todas as etapas do ataque foram reproduzidas com **sincronismo NTP Stratum 1 (`a.st1.ntp.br`)**, coleta centralizada no SIEM (`RT-12`), disparo das **4 regras de detecção (`RT-13`)**, resposta automatizada **SOAR com trava humana (`RT-15`)** e preservação imediata com **hash criptográfico SHA-256**.

---

## 2. Aquisição de Evidências e Hashes SHA-256 (RT-14)

Todas as evidências digitais foram adquiridas logicamente em modo somente-leitura no diretório `forensics/evidence/` em **`2026-11-16T03:27:52.191907+00:00 (UTC/NTP)`**, com cálculo imediato do resumo criptográfico **SHA-256** (registrado em `forensics/cadeia_de_custodia.json`):

| ID Evidência | Arquivo Adquirido | Tamanho (Bytes) | Hash SHA-256 Verificável | Descrição Técnica do Artefato |
| :---: | :--- | :---: | :--- | :--- |
| **EVD-01** | `EVD-01_central_siem_logs.jsonl` | `5.854` | `7b4882dc637a7da2013ed46bd290f9f09afd0370a3548f96385dfe9725d866a2` | Repositório centralizado de logs JSONL sincronizados via NTP contendo os 7 eventos da intrusão. |
| **EVD-02** | `EVD-02_siem_triggered_alerts.jsonl` | `1.649` | `b1b852b7becdc4bfa789075317f73262ea0c65454375a0da3de43d744d82d940` | Alertas gerados em tempo real pelas 4 regras obrigatórias do SIEM (`100710` a `100713`). |
| **EVD-03** | `EVD-03_sqli_forensic_artifact.json` | `1.420` | `edba9e9d59359f1596929aac9d08a665bc493b1ec218da9d70e759379a7bf7c2` | Evidência da consulta SQL injetada (`UNION SELECT`) e dos registros extraídos no painel legado. |
| **EVD-04** | `EVD-04_soar_response_and_human_queue.json` | `2.264` | `446240b83077eb7cd55b3cfd135cf5ed22d9710591e33706f3d9d1afc9af3480` | Registro das ações automáticas de contenção SOAR e retenção de alto impacto (`APPROVAL-001`). |

---

## 3. Registro Formal de Cadeia de Custódia (ISO/IEC 27037)

| Campo da Cadeia de Custódia | Registro Oficial do Caso `INC-VA-0712` |
| :--- | :--- |
| **Identificador do Caso** | `INC-VA-0712` (Reprodução Controlada de Laboratório) |
| **Responsável pela Coleta (Perito)** | `Perito_Forense_Digital_Equipe_FIAP (ID Sintético: AUDITOR-04)` |
| **Data e Hora da Aquisição (NTP UTC)** | `2026-11-16T03:27:52.191907+00:00` (Sincronizado com `a.st1.ntp.br`, desvio < 15 ms) |
| **Local de Coleta** | Laboratório Isolado Docker — Rede Vila Aurora (Host Centralizador SIEM/SOAR) |
| **Método de Aquisição** | Extração lógica imutável com geração simultânea de manifesto SHA-256 (`scripts/reproduce_inc_va_0712.py`) |
| **Histórico de Movimentação e Lacre** | `Coleta -> Cálculo Hash SHA-256 -> Armazenamento Read-Only em forensics/evidence/ -> Conferência de Integridade Pericial (100% Íntegro)` |

---

## 4. Linha do Tempo Consolidada e Mapeamento MITRE ATT&CK (RT-13, RT-14, RT-15)

A correlação dos logs sincronizados por NTP em `EVD-01` e `EVD-02` permite reconstruir com precisão de segundos toda a sequência do ataque e a resposta automática da nova arquitetura:

| Timestamp (NTP UTC) | Origem / Componente | Evento Reconstruído | Técnica MITRE ATT&CK / ATLAS | Regra SIEM Disparada (RT-13) | Resposta Automatizada SOAR / Borda (RT-15) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-25T21:42:10Z` | `email_gateway` (`203.0.113.45`) | Recebimento de e-mail de spear-phishing gerado por IA simulando a Prefeitura + áudio de WhatsApp com voz clonada do Secretário Municipal. | **T1566.002** (Spearphishing Link) / **AML.T0054** (AI Deepfake) | Bloqueio Preventivo DMARC (`RT-10`) + Protocolo Fora de Banda (`RT-18`) | E-mail sem alinhamento DKIM/SPF colocado em quarentena; exigida Palavra-Código verbal. |
| `2026-10-25T21:48:55Z` | `phishing_landing` (`203.0.113.45`) | Submissão de usuário e senha de `coordenacao03` na página falsa (no cenário legado sem MFA). | **T1598.003** (Phishing for Information) | Monitoramento de Identidade | Na nova arquitetura, a senha isolada é inútil sem a chave WireGuard e sem o token MFA TOTP. |
| `2026-10-26T02:14:03Z` | `vpn_gateway` (`198.51.100.99`) | Login na VPN durante a madrugada (`02h14`) a partir de IP externo desconhecido (`198.51.100.99`). | **T1078** (Valid Accounts) / **T1133** (External Remote Services) | **`WAZUH-100710`** (`RT-13a`: Login VPN Anômalo - Nível 12) | **SOAR Baixo Risco:** Sessão VPN de `coordenacao03` encerrada imediatamente e IP `198.51.100.99` bloqueado no firewall. |
| `2026-10-26T02:17:29Z` | `web_panel` (`198.51.100.99`) | Injeção SQL (`UNION SELECT ... FROM operators_credentials`) no campo de busca do histórico de acessos. | **T1190** (Exploit Public-Facing App) / **T1005** (Data from Local System) | **`WAZUH-100711`** (`RT-13b`: Padrão de SQL Injection - Nível 14) | **WAF + SOAR:** Requisição bloqueada com `HTTP 403` na rota corrigida e IP bloqueado permanentemente. |
| `2026-10-26T02:19:44Z` | `edge_controller` (`198.51.100.99`) | Tentativa de alterar o agendamento da bomba d'água da Escola (`escola-bomba-recalque-01`) na madrugada. | **T1565.001** (Stored Data Manipulation) / **T0855** (Unauthorized Command) | **`WAZUH-100713`** (`RT-13d`: Comando de Atuador Fora de Horário - Nível 15) | **SOAR + Human-in-the-Loop:** Bomba colocada em **Modo Seguro Local** (40%–85%); desligamento total retido na fila humana **`APPROVAL-001`** exigindo MFA da Coordenação. |
| `2026-10-26T02:22:15Z` | `mosquitto_edge` (`172.28.10.99`) | Tentativa de conexão MQTT por dispositivo com certificado revogado/inválido (`sensor-comprometido-99`). | **T1552.004** (Private Keys) / **T1200** (Hardware Additions) | **`WAZUH-100712`** (`RT-13c`: Dispositivo sem Certificado Válido - Nível 13) | **SOAR Baixo Risco:** Dispositivo isolado na ACL do Broker e certificado revogado na `certs/crl.pem`. |
| `2026-10-26T03:05:00Z` | `edge_controller` (`ubs-camara-fria-01`) | Queda do link de fibra durante temporal e subida da temperatura da câmara fria da UBS para `11,4 °C`. | **T1498** (Network Denial of Service / Impacto Ambiental) | Regra Autônoma de Borda (`EDGE_RULE_UBS_VACCINE_TEMP`) | **Borda Autônoma (`RT-02`):** Sirene local da UBS ativada + compressor reserva ligado offline + failover para modem **4G LTE (`RT-03`)**. |

---

## 5. Conclusões Periciais e Recomendações Técnicas

### 5.1 Conclusões da Investigação
1. **Causa Raiz da Intrusão Inicial:** O vetor primário do incidente `INC-VA-0712` foi o comprometimento de credenciais da coordenação por **engenharia social potencializada por IA (e-mail + áudio com voz clonada)**, agravado pela ausência de **MFA** na VPN legada.
2. **Causa Raiz do Impacto nos Dados e na Bomba da Escola:** A falta de parametrização SQL no painel legado permitiu a extração da tabela de operadores via `UNION SELECT` (`EVD-03`) e a manipulação do agendamento da bomba de recalque às `02h19 UTC`.
3. **Causa Raiz do Incidente Sanitário na UBS:** A arquitetura antiga concentrava as regras de alerta exclusivamente na nuvem; quando a fibra rompeu às `03h05 UTC`, a elevação de temperatura da câmara fria de vacinas não gerou alarme local.
4. **Eficácia Comprovada da Nova Arquitetura:** Na reprodução em bancada com a nova arquitetura implementada, **100% dos vetores do `INC-VA-0712` foram neutralizados** em menos de 2 segundos pelas 4 regras do SIEM (`EVD-02`), pelos playbooks SOAR (`EVD-04`) e pela operação autônoma do Nó de Borda (`RT-02`).

### 5.2 Recomendações Pós-Incidente
1. **Manter Obrigatoriedade de MFA e Verificação Fora de Banda:** Nunca permitir exceções de login na VPN sem token TOTP e manter a **Palavra-Código Semanal** para qualquer solicitação operacional extraordinária.
2. **Auditoria Contínua de Integridade de Logs:** Verificar semanalmente os hashes SHA-256 dos arquivos de log arquivados e monitorar o status de sincronização NTP em todos os 5 nós de borda.
3. **Treinamento Periódico com Voluntários:** Realizar simulações éticas trimestrais de phishing para manter a taxa de reporte ao SOC acima de 80%.
