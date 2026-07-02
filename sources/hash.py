"""
Fontes de investigação para IOCs do tipo hash (MD5 / SHA256).
Consulta: MalwareBazaar (abuse.ch) + VirusTotal

MalwareBazaar não exige autenticação — é uma API pública do abuse.ch
focada em amostras de malware conhecidas.
"""
import os
import requests

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
TIMEOUT = 8


def consultar_malwarebazaar(hash_valor):
    try:
        headers = {}
        if URLHAUS_AUTH_KEY:
            headers["Auth-Key"] = URLHAUS_AUTH_KEY

        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_valor},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {"fonte": "MalwareBazaar", "status": "erro", "detalhe": f"HTTP {resp.status_code}", "dados": {}}

        dados = resp.json()
        query_status = dados.get("query_status", "")

        if query_status == "hash_not_found":
            return {"fonte": "MalwareBazaar", "status": "limpo", "detalhe": "Hash não encontrado na base", "dados": {}}

        if query_status == "ok":
            info = dados["data"][0]
            familia = info.get("signature") or "desconhecida"
            tags = info.get("tags") or []
            tipo = info.get("file_type", "N/A")
            tamanho = info.get("file_size", 0)
            first_seen = info.get("first_seen", "—")

            return {
                "fonte": "MalwareBazaar",
                "status": "malicioso",
                "detalhe": f"Família: {familia} | Tipo: {tipo} | First seen: {first_seen}",
                "dados": {
                    "familia": familia,
                    "tags": tags,
                    "tipo_arquivo": tipo,
                    "tamanho_bytes": tamanho,
                    "first_seen": first_seen,
                    "sha256": info.get("sha256_hash"),
                    "md5": info.get("md5_hash"),
                    "nome_arquivo": info.get("file_name"),
                }
            }

        return {"fonte": "MalwareBazaar", "status": "erro", "detalhe": f"Status inesperado: {query_status}", "dados": {}}

    except Exception as e:
        return {"fonte": "MalwareBazaar", "status": "erro", "detalhe": str(e), "dados": {}}


def consultar_virustotal_hash(hash_valor):
    if not VIRUSTOTAL_API_KEY:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": "API key ausente", "dados": {}}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_valor}",
            headers=headers, timeout=TIMEOUT
        )

        if resp.status_code == 404:
            return {"fonte": "VirusTotal", "status": "limpo", "detalhe": "Hash não encontrado na base", "dados": {}}
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
                "nome": attrs.get("meaningful_name"),
                "tipo": attrs.get("type_description"),
                "tamanho": attrs.get("size"),
                "first_submission": str(attrs.get("first_submission_date", "—")),
            }
        }
    except Exception as e:
        return {"fonte": "VirusTotal", "status": "erro", "detalhe": str(e), "dados": {}}


def investigar_hash(hash_valor):
    return [consultar_malwarebazaar(hash_valor), consultar_virustotal_hash(hash_valor)]
