"""
Integração com MITRE ATT&CK.

Usa a API pública do MITRE (TAXII/STIX via attackcti ou requests direto
ao GitHub do MITRE) pra buscar técnicas relacionadas ao contexto do IOC.

Como o ATT&CK não indexa IOCs diretamente (ele indexa técnicas/táticas),
a abordagem é: extrair palavras-chave dos resultados das fontes (ex:
"phishing", "botnet", "ransomware", "C2") e mapear pras técnicas
relevantes do ATT&CK via busca por texto nos dados locais.

Os dados do ATT&CK Enterprise são baixados uma vez e cacheados em memória.
"""
import requests
import time

_ttp_cache = []
_ttp_cache_ts = 0
_TTP_TTL = 86400  # recarrega uma vez por dia


def _carregar_attack():
    global _ttp_cache, _ttp_cache_ts
    if time.time() - _ttp_cache_ts < _TTP_TTL and _ttp_cache:
        return

    try:
        # Usa a versão compacta do ATT&CK (só técnicas, sem subtécnicas e objetos relacionados)
        # Muito menor que o JSON completo (~2MB vs ~50MB)
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        resp = requests.get(url, timeout=15)  # timeout curto — se falhar, usa keywords locais
        if resp.status_code != 200:
            print(f"[mitre] Falha ao carregar ATT&CK: HTTP {resp.status_code} — usando keywords locais")
            _ttp_cache_ts = time.time()  # marca como "tentado" pra não tentar de novo em toda chamada
            return

        stix = resp.json()
        tecnicas = []
        for obj in stix.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            external = obj.get("external_references", [])
            mitre_id = next((r["external_id"] for r in external if r.get("source_name") == "mitre-attack"), None)
            if not mitre_id:
                continue

            tecnicas.append({
                "id": mitre_id,
                "nome": obj.get("name", ""),
                "descricao": obj.get("description", "")[:300],
                "taticas": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
            })

        _ttp_cache = tecnicas
        _ttp_cache_ts = time.time()
        print(f"[mitre] {len(tecnicas)} técnicas carregadas do ATT&CK.")

    except Exception as e:
        print(f"[mitre] Erro ao carregar ATT&CK ({e}) — usando keywords locais como fallback")
        _ttp_cache_ts = time.time()  # evita retry em toda chamada na mesma sessão


# Mapeamento de palavras-chave (extraídas dos resultados das fontes) para
# IDs de técnicas ATT&CK relevantes — garante resultados mesmo sem internet
KEYWORDS_TECNICAS = {
    "phishing":         ["T1566", "T1566.001", "T1566.002"],
    "botnet":           ["T1583.001", "T1587.001", "T1584"],
    "malware":          ["T1204", "T1059", "T1055"],
    "ransomware":       ["T1486", "T1489", "T1490"],
    "c2":               ["T1071", "T1095", "T1571"],
    "command":          ["T1071", "T1095"],
    "exploit":          ["T1203", "T1190", "T1068"],
    "brute":            ["T1110", "T1110.001"],
    "scan":             ["T1595", "T1046"],
    "ddos":             ["T1498", "T1499"],
    "trojan":           ["T1204", "T1059"],
    "backdoor":         ["T1543", "T1546"],
    "keylogger":        ["T1056", "T1056.001"],
    "stealer":          ["T1555", "T1539"],
    "dropper":          ["T1105", "T1204"],
    "miner":            ["T1496"],
    "proxy":            ["T1090", "T1090.002"],
    "spam":             ["T1566", "T1598"],
    "alert":            ["T1566", "T1598"],
    "security-alert":   ["T1566", "T1598"],
    "powershell":       ["T1059", "T1059.001"],
    "script":           ["T1059", "T1064"],
    "malicious":        ["T1204", "T1071"],
    "engines detectaram": ["T1204", "T1071"],
    "ameaça":           ["T1204", "T1071"],
}


def buscar_ttps(contexto_texto):
    """
    Recebe texto livre (detalhes das fontes concatenados) e retorna
    lista de TTPs do MITRE ATT&CK relevantes ao contexto.
    """
    _carregar_attack()

    contexto_lower = contexto_texto.lower()
    ids_encontrados = set()

    for keyword, ids in KEYWORDS_TECNICAS.items():
        if keyword in contexto_lower:
            ids_encontrados.update(ids)

    if not ids_encontrados:
        return []

    # Enriquece com nome e táticas a partir do cache
    ttps = []
    for tecnica in _ttp_cache:
        if tecnica["id"] in ids_encontrados:
            ttps.append(tecnica)
            ids_encontrados.discard(tecnica["id"])

    # Se não achou no cache (ex: cache vazio por falha de rede),
    # retorna pelo menos o ID com nome genérico
    for id_restante in ids_encontrados:
        ttps.append({
            "id": id_restante,
            "nome": "Técnica ATT&CK",
            "descricao": "",
            "taticas": [],
        })

    return ttps
