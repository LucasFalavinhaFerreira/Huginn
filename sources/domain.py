"""
Fontes de investigação para IOCs do tipo domínio ou URL.
Consulta: URLhaus + OpenPhish + VirusTotal
"""
import os
import time
import requests

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
TIMEOUT = 8

_openphish_cache = set()
_openphish_ts = 0


def _carregar_openphish():
    global _openphish_cache, _openphish_ts
    if time.time() - _openphish_ts < 3600 and _openphish_cache:
        return
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=TIMEOUT)
        if resp.status_code == 200:
            _openphish_cache = set(l.strip().lower() for l in resp.text.splitlines() if l.strip())
            _openphish_ts = time.time()
    except Exception as e:
        print(f"[sources.domain] Falha ao carregar OpenPhish: {e}")


def consultar_urlhaus(alvo):
    if not URLHAUS_AUTH_KEY:
        return {"fonte": "URLhaus", "status": "erro", "detalhe": "Auth-Key ausente", "dados": {}}
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": alvo},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {"fonte": "URLhaus", "status": "erro", "detalhe": f"HTTP {resp.status_code}", "dados": {}}

        dados = resp.json()
        qs = dados.get("query_status", "")

        if qs in ("is_url", "is_host"):
            urls = dados.get("urls", [dados]) if qs == "is_host" else [dados]
            online = [u for u in urls if u.get("url_status") == "online"]
            tags = online[0].get("tags") or [] if online else dados.get("tags") or []
            status = "malicioso" if online else "suspeito"
            return {
                "fonte": "URLhaus",
                "status": status,
                "detalhe": f"{'URL ativa' if online else 'Registrado (offline)'} | tags: {', '.join(tags) or 'sem tag'}",
                "dados": {"tags": tags, "url_status": "online" if online else "offline"},
            }
        return {"fonte": "URLhaus", "status": "limpo", "detalhe": "Não encontrado na base", "dados": {}}
    except Exception as e:
        return {"fonte": "URLhaus", "status": "erro", "detalhe": str(e), "dados": {}}


def consultar_openphish(alvo):
    try:
        _carregar_openphish()
        alvo_lower = alvo.lower().strip()
        dominio = alvo_lower.replace("https://", "").replace("http://", "").split("/")[0]
        if alvo_lower in _openphish_cache:
            return {"fonte": "OpenPhish", "status": "malicioso", "detalhe": "URL exata encontrada no feed", "dados": {}}
        matches = [u for u in _openphish_cache if dominio in u]
        if matches:
            return {"fonte": "OpenPhish", "status": "malicioso", "detalhe": f"Domínio em {len(matches)} URL(s) de phishing", "dados": {"matches": len(matches)}}
        return {"fonte": "OpenPhish", "status": "limpo", "detalhe": "Não encontrado no feed", "dados": {}}
    except Exception as e:
        return {"fonte": "OpenPhish", "status": "erro", "detalhe": str(e), "dados": {}}


def consultar_virustotal_dominio(alvo):
    if not VIRUSTOTAL_API_KEY:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": "API key ausente", "dados": {}}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        if alvo.startswith("http://") or alvo.startswith("https://"):
            import base64
            url_id = base64.urlsafe_b64encode(alvo.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{alvo}"

        resp = requests.get(endpoint, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 404:
            return {"fonte": "VirusTotal", "status": "limpo", "detalhe": "Não encontrado na base", "dados": {}}
        if resp.status_code != 200:
            return {"fonte": "VirusTotal", "status": "erro", "detalhe": f"HTTP {resp.status_code}", "dados": {}}

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        status = "malicioso" if malicious > 2 else "suspeito" if malicious > 0 or suspicious > 0 else "limpo"

        return {
            "fonte": "VirusTotal",
            "status": status,
            "detalhe": f"{malicious}/{total} engines detectaram ameaça",
            "dados": {"malicious": malicious, "suspicious": suspicious, "total_engines": total},
        }
    except Exception as e:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": str(e), "dados": {}}


def investigar_dominio(alvo):
    return [consultar_urlhaus(alvo), consultar_openphish(alvo), consultar_virustotal_dominio(alvo)]
