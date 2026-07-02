"""
Fontes de investigação para IOCs do tipo IP.
Consulta: AbuseIPDB + VirusTotal
"""
import os
import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
TIMEOUT = 8


def consultar_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"fonte": "AbuseIPDB", "status": "erro", "detalhe": "API key ausente", "dados": {}}

    try:
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=TIMEOUT
        )
        if resp.status_code != 200:
            return {"fonte": "AbuseIPDB", "status": "erro", "detalhe": f"HTTP {resp.status_code}", "dados": {}}

        dados = resp.json()["data"]
        score = dados.get("abuseConfidenceScore", 0)
        status = "malicioso" if score > 50 else "suspeito" if score > 10 else "limpo"

        return {
            "fonte": "AbuseIPDB",
            "status": status,
            "detalhe": f"Score de abuso: {score}% | País: {dados.get('countryCode', 'N/A')} | ISP: {dados.get('isp', 'N/A')}",
            "dados": {
                "score": score,
                "pais": dados.get("countryCode"),
                "isp": dados.get("isp"),
                "total_reports": dados.get("totalReports", 0),
                "ultima_denuncia": str(dados.get("lastReportedAt", "—")),
                "dominio": dados.get("domain"),
                "uso": dados.get("usageType"),
            }
        }
    except Exception as e:
        return {"fonte": "AbuseIPDB", "status": "erro", "detalhe": str(e), "dados": {}}


def consultar_virustotal_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": "API key ausente", "dados": {}}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=TIMEOUT
        )
        if resp.status_code == 404:
            return {"fonte": "VirusTotal", "status": "limpo", "detalhe": "IP não encontrado na base", "dados": {}}
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
            "dados": {
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "pais": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputacao": attrs.get("reputation", 0),
            }
        }
    except Exception as e:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": str(e), "dados": {}}


def investigar_ip(ip):
    return [consultar_abuseipdb(ip), consultar_virustotal_ip(ip)]
