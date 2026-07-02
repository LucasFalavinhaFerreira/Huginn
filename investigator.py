import re
import time
from sources.ip import investigar_ip
from sources.domain import investigar_dominio
from sources.hash import investigar_hash
from mitre import buscar_ttps
from db import salvar_investigacao
from reporter import gerar_relatorio_html

VT_SLEEP = 16
REGEX_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
REGEX_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
REGEX_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def detectar_tipo(ioc):
    ioc = ioc.strip()
    if REGEX_IPV4.match(ioc):
        return "ip"
    if REGEX_MD5.match(ioc) or REGEX_SHA256.match(ioc):
        return "hash"
    return "dominio"


def calcular_veredito(resultados):
    pontos = {"malicioso": 2, "suspeito": 1, "limpo": 0, "erro": 0}
    score = sum(pontos.get(r["status"], 0) for r in resultados)
    if score >= 4:
        return "🔴 CRÍTICO", score
    if score >= 2:
        return "🟡 SUSPEITO", score
    if score >= 1:
        return "🟠 ATENÇÃO", score
    return "🟢 LIMPO", score


def investigar(ioc):
    ioc = ioc.strip()
    tipo = detectar_tipo(ioc)
    time.sleep(VT_SLEEP)

    if tipo == "ip":
        resultados = investigar_ip(ioc)
    elif tipo == "hash":
        resultados = investigar_hash(ioc)
    else:
        resultados = investigar_dominio(ioc)

    veredito, score = calcular_veredito(resultados)

    contexto_partes = [ioc, tipo]
    contexto_partes += [r.get("detalhe", "") for r in resultados]
    contexto_partes += [str(r.get("dados", {})) for r in resultados]
    contexto = " ".join(contexto_partes)
    print(f"[investigator] contexto para TTPs: {contexto[:200]}")

    ttps = buscar_ttps(contexto)
    print(f"[investigator] TTPs encontradas: {len(ttps)}")

    detalhes = {r["fonte"]: {"status": r["status"], "detalhe": r["detalhe"], "dados": r.get("dados", {})} for r in resultados}
    relatorio_html = gerar_relatorio_html(ioc, tipo, veredito, score, resultados, ttps)
    investigacao_id = salvar_investigacao(
        ioc=ioc, tipo=tipo, veredito=veredito, score=score,
        detalhes=detalhes, ttps=ttps, relatorio_html=relatorio_html,
    )

    return {
        "id": investigacao_id,
        "ioc": ioc,
        "tipo": tipo,
        "veredito": veredito,
        "score": score,
        "resultados": resultados,
        "ttps": ttps,
        "relatorio_html": relatorio_html,
    }
