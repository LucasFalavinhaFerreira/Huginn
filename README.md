# 🦅 Huginn — Playbook de Investigação de IOC

> *Na mitologia nórdica, Huginn (pensamento) e Muninn (memória) são os corvos de Odin. Huginn parte pelo mundo para coletar informação; Muninn guarda tudo que foi aprendido. Esta ferramenta faz exatamente isso: investiga IOCs em múltiplas fontes e persiste o histórico completo.*

Huginn é um playbook automatizado de investigação de Indicadores de Comprometimento (IOC). Recebe um IP, domínio, URL ou hash, detecta o tipo automaticamente, consulta múltiplas fontes de Threat Intelligence em paralelo, mapeia TTPs do MITRE ATT&CK e gera um relatório HTML estruturado — pronto para ser anexado num ticket de incidente.

---

## ✨ Funcionalidades

- **Detecção automática de tipo** — IP, domínio/URL ou hash MD5/SHA256, sem configuração manual
- **5 fontes de Threat Intelligence** consultadas por investigação
- **Mapeamento de TTPs do MITRE ATT&CK** com base no contexto dos resultados
- **Relatório HTML exportável** com sumário executivo, detalhes por fonte, TTPs e recomendações
- **Histórico persistente (Muninn)** — todas as investigações salvas no Postgres, recarregáveis pelo ID
- **Dashboard Gradio** com duas abas: investigação e histórico

---

## 🔍 Fontes por Tipo de IOC

| Tipo | Fontes |
|------|--------|
| **IP** | AbuseIPDB, VirusTotal |
| **Domínio / URL** | URLhaus (abuse.ch), OpenPhish, VirusTotal |
| **Hash (MD5/SHA256)** | MalwareBazaar (abuse.ch), VirusTotal |

---

## 🛡️ MITRE ATT&CK

O mapeamento de TTPs é feito automaticamente com base no contexto agregado dos resultados — família de malware, tipo de ameaça, comportamento detectado. Os dados do ATT&CK Enterprise são carregados via STIX/GitHub do MITRE (público, sem autenticação) e cacheados em memória.

Exemplo: um domínio com padrão de phishing retorna automaticamente:
- `T1566` — Phishing (initial-access)
- `T1598` — Phishing for Information (reconnaissance)
- `T1204` — User Execution (execution)

---

## 🗂️ Estrutura do Projeto

```
huginn/
├── .github/workflows/ci.yml   # Valida sintaxe a cada push
├── sources/
│   ├── ip.py                  # AbuseIPDB + VirusTotal
│   ├── domain.py              # URLhaus + OpenPhish + VirusTotal
│   └── hash.py                # MalwareBazaar + VirusTotal
├── db.py                      # Postgres — histórico de investigações (Muninn)
├── mitre.py                   # Integração MITRE ATT&CK
├── investigator.py            # Motor central de investigação
├── reporter.py                # Gerador de relatório HTML
├── app.py                     # Dashboard Gradio
├── requirements.txt
└── .env.example
```

---

## 🚀 Como Rodar Localmente

**Pré-requisitos:** Python 3.11+, conta no [Neon](https://neon.tech) (Postgres gratuito)

```bash
git clone https://github.com/SEU_USUARIO/huginn
cd huginn
pip install -r requirements.txt
cp .env.example .env
# Preencha o .env com suas credenciais
python app.py
```

**Variáveis de ambiente necessárias:**

| Variável | Descrição | Onde obter |
|----------|-----------|------------|
| `DATABASE_URL` | Connection string do Postgres | [neon.tech](https://neon.tech) |
| `ABUSEIPDB_API_KEY` | API Key do AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| `VIRUSTOTAL_API_KEY` | API Key do VirusTotal | [virustotal.com](https://www.virustotal.com) |
| `URLHAUS_AUTH_KEY` | Auth-Key do abuse.ch | [auth.abuse.ch](https://auth.abuse.ch) |

> Todas as APIs usadas têm tier gratuito. Nenhuma chave paga necessária.

---

## 🏗️ Infraestrutura

| Componente | Serviço | Custo |
|------------|---------|-------|
| Banco de dados | Neon (Postgres gerenciado) | Gratuito |
| CI/CD | GitHub Actions | Gratuito |
| Dashboard | Hugging Face Spaces | Gratuito |

**Custo total de infraestrutura: $0**

---

## 🔗 Projetos Relacionados

Este projeto faz parte de uma trilha de SOC tooling:

- [**Sentinela SOC**](https://github.com/SEU_USUARIO/sentinela-soc) — Pipeline de Threat Intelligence: coleta 7 feeds públicos de IPs maliciosos, enriquece via AbuseIPDB, persiste em Postgres e alerta via Slack. Automação via GitHub Actions (cron 6h).
- [**Argus**](https://github.com/SEU_USUARIO/argus) — Verificador de domínios e URLs: consulta URLhaus, OpenPhish e VirusTotal, com monitoramento contínuo e alertas no Slack.
- **Huginn** ← você está aqui

---

## ⚠️ Aviso Legal

Este projeto usa exclusivamente APIs e feeds públicos de Threat Intelligence para fins educacionais e de portfólio pessoal. As APIs do VirusTotal e AbuseIPDB têm termos de uso próprios — consulte-os antes de usar em ambiente corporativo ou comercial.

---

*Desenvolvido por [Lucas Falavinha Ferreira](https://linkedin.com/in/SEU_PERFIL)*
