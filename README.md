# Rede Comunitária Vila Aurora — Resilient Community Infrastructure
**FIAP · Global Solution 2026.2 · Cybersecurity · Turma: 4ECR**  
**Professor:** Prof. Carlos Eduardo de Siqueira  
**Repositório Oficial (E2):** [https://github.com/Felipehoc/global_solutions_Resilient_Community_Infrastructure](https://github.com/Felipehoc/global_solutions_Resilient_Community_Infrastructure)

### Integrantes da Equipe (Turma 4ECR)
- **Felipe Henrique de Oliveira Cruz** — RM 552566
- **Octhor Festa** — RM 552533

Protótipo funcional completo de infraestrutura computacional segura, resiliente e modular para monitoramento e coordenação de recursos essenciais dos **5 espaços comunitários da Rede Vila Aurora** (Centro Comunitário, Escola Municipal, Unidade Básica de Saúde - UBS, Horta/Cozinha Solidária e Abrigo de Emergência da Defesa Civil).

---

## Sumário Rápido dos Entregáveis

| ID | Entregável | Localização no Repositório |
| :--- | :--- | :--- |
| **E1** | **Documento de Arquitetura, Modelo de Ameaças (STRIDE), Redundância, LGPD/RIPD e Custos** | [`docs/E1_Documento_Arquitetura.md`](docs/E1_Documento_Arquitetura.md) |
| **E2** | **Protótipo Funcional, Scripts, Docker Compose, Dados Sintéticos e Guia Reproduzível** | Este repositório (`src/`, `configs/`, `scripts/`, `docker-compose.yml`) |
| **E3** | **Relatório de Testes de Segurança (SQLi Antes/Depois, mTLS/CRL, VPN/MFA, SPF/DKIM/DMARC, Phishing, IA/LLM)** | [`docs/E3_Relatorio_Testes_Seguranca.md`](docs/E3_Relatorio_Testes_Seguranca.md) |
| **E4** | **Laudo Pericial Forense Digital do Incidente `INC-VA-0712` (Hashes SHA-256, Cadeia de Custódia, Timeline, MITRE ATT&CK)** | [`docs/E4_Laudo_Forense_INC_VA_0712.md`](docs/E4_Laudo_Forense_INC_VA_0712.md) |
| **Consolidado** | **Relatório Técnico Único Consolidado (E1 + E3 + E4 separados por seção oficial)** | [`docs/Relatorio_Tecnico_Consolidado_E1_E3_E4.md`](docs/Relatorio_Tecnico_Consolidado_E1_E3_E4.md) |

---

## Como Reproduzir o Ambiente Passo a Passo (Entregável E2)

O projeto foi desenhado sob o princípio de **Complexidade Mínima e Reprodutibilidade Total**: todos os módulos funcionam **nativamente com Python 3.11+** (mesmo sem dependências externas, graças aos fallbacks determinísticos integrados) ou via **Docker Compose**.

### Opção A — Execução Direta Rápida (Em menos de 5 segundos)

1. **Executar a bateria completa de testes, simulação do incidente `INC-VA-0712`, teste de caos de 35 minutos e geração de evidências forenses (RT-01 a RT-23):**
   ```bash
   python scripts/run_all_tests_and_evidence.py
   ```
   Isso irá:
   - Gerar a Autoridade Certificadora (`VilaAurora-Root-CA`) e os certificados X.509 individuais em `certs/` (`RT-04`).
   - Revogar o dispositivo comprometido `sensor-comprometido-99` na `certs/crl.pem` e rotacionar credenciais (`RT-05`).
   - Demonstrar a exploração de **SQL Injection** na rota legada vulnerável e o bloqueio na rota corrigida parametrizada + WAF (`RT-08`).
   - Validar os registros **SPF, DKIM e DMARC (`p=quarantine`)** e executar a simulação ética de phishing contra as 5 contas sintéticas (`RT-10`, `RT-11`, `RT-18`).
   - Reproduzir o incidente **`INC-VA-0712`**, disparar as **4 regras do SIEM** (`RT-12`, `RT-13`), acionar os playbooks **SOAR** com retenção humana para alto impacto (`RT-15`) e lacrar as evidências com **SHA-256** em `forensics/cadeia_de_custodia.json` (`RT-14`).
   - Treinar e avaliar o modelo **Isolation Forest** sobre a telemetria (`RT-16`) e testar os **Guardrails contra Prompt Injection Direto/Indireto** (`RT-17`).
   - Executar o **Teste de Caos Controlado** derrubando o link WAN por **35 minutos** e comprovando atuação local autônoma da borda e reconciliação com **0% de perda de dados** (`RT-02`, `RT-22`, `RT-23`).

2. **Subir o Painel Web Acessível (WCAG 2.1 AA) localmente:**
   ```bash
   python -m src.backend.app --host 127.0.0.1 --port 8080
   ```
   Acesse no navegador: `http://127.0.0.1:8080`

3. **Executar scripts individuais de teste:**
   ```bash
   python scripts/test_sqli_before_after.py
   python scripts/run_phishing_simulation.py
   python scripts/reproduce_inc_va_0712.py
   python scripts/chaos_test_wan.py
   ```

### Opção B — Execução Completa Containerizada via Docker Compose

```bash
cp .env.example .env
docker compose up --build -d
```

---

## Estrutura do Repositório

- `src/pki/pki_manager.py`: Emissão de certificados X.509 únicos por dispositivo, validação mTLS, revogação via CRL e rotação de credenciais (`RT-04`, `RT-05`).
- `src/field_simulators/iot_simulator.py`: Simuladores de sensores e atuadores dos 5 espaços comunitários (`RT-01`).
- `src/edge_node/autonomous_agent.py`: Nó de borda autônomo com regras locais determinísticas, buffer SQLite *store-and-forward*, reconciliação pós-queda e failover 4G / modo degradado (`RT-01`, `RT-02`, `RT-03`).
- `src/backend/app.py`, `auth.py`, `privacy.py`: Painel de supervisão com queries parametrizadas, WAF, validação de entrada, menor privilégio, RBAC (4 perfis), MFA TOTP RFC 6238 e pseudonimização LGPD (`RT-08`, `RT-09`, `RT-19`).
- `src/frontend/index.html`: Interface acessível WCAG 2.1 nível AA em português simples para voluntários (`RT-21`).
- `src/siem_soar/siem_engine.py`, `soar_playbook.py`: Centralização de logs NTP, 4 regras de detecção compatíveis com Wazuh e automação SOAR com aprovação humana para ações críticas (`RT-12`, `RT-13`, `RT-15`).
- `src/ai_defense/anomaly_detector.py`, `llm_guardrails.py`: Detecção de anomalias em telemetria via `Isolation Forest` e guardrails de LLM contra Prompt Injection mapeados no OWASP LLM Top 10 e MITRE ATLAS (`RT-16`, `RT-17`).
- `configs/`: Configurações do Mosquitto (`mTLS` + `crlfile`), WireGuard VPN + Firewall Zero Trust (`RT-06`, `RT-07`), Zona DNS (`SPF`, `DKIM`, `DMARC`) e regras XML do Wazuh (`local_rules.xml`).
- `forensics/`: Evidências coletadas (`EVD-01` a `EVD-04`), hashes SHA-256 e cadeia de custódia do incidente `INC-VA-0712` (`RT-14`).

---

## Declaração Ética, Legal e de Uso de IA (Seção 7 do Desafio)

1. **Isolamento de Testes Ofensivos:** Todos os testes de SQL Injection, phishing simulado e Prompt Injection ocorrem exclusivamente em banco SQLite local e containers isolados da própria equipe, sem qualquer interação com sistemas externos.
2. **Dados 100% Sintéticos (LGPD):** Nenhum dado pessoal real foi utilizado. Todas as 5 contas (`@vilaaurora.org.br`) e crachás RFID são fictícios e pseudonimizados com HMAC-SHA256.
3. **Zero Segredos no Git:** Chaves privadas (`.key`, `.pem`) são ignoradas pelo `.gitignore` e geradas dinamicamente em tempo de execução pelo `pki_manager.py`.
4. **Declaração de Uso de IA Generativa:** Utilizou-se o assistente Antigravity (Gemini) como apoio para estruturação de código, revisão dos modelos de ameaças STRIDE/MITRE ATT&CK e formatação padronizada da documentação técnica, sendo todo o código e resultados revisados, executados e validados tecnicamente pela equipe.
