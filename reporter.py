"""
Gerador de relatório de investigação do Huginn.

Produz um relatório HTML completo e estruturado,
pronto pra ser exportado como arquivo ou salvo no banco.
"""
from datetime import datetime


CORES_VEREDITO = {
    "CRÍTICO": "#ff4444",
    "SUSPEITO": "#ffaa00",
    "ATENÇÃO":  "#ff7700",
    "LIMPO":    "#00ff9d",
}

CORES_STATUS = {
    "malicioso": "#ff4444",
    "suspeito":  "#ffaa00",
    "limpo":     "#00ff9d",
    "erro":      "#888888",
    "-":         "#888888",
}


def _cor_veredito(veredito):
    for k, v in CORES_VEREDITO.items():
        if k in veredito:
            return v
    return "#ffffff"


def gerar_relatorio_html(ioc, tipo, veredito, score, resultados, ttps):
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    cor = _cor_veredito(veredito)

    # Bloco de resultados por fonte
    fontes_html = ""
    for r in resultados:
        cor_status = CORES_STATUS.get(r["status"], "#ffffff")
        dados = r.get("dados", {})
        dados_html = ""
        if dados:
            dados_html = "<ul style='margin:6px 0 0 16px;padding:0;color:#aaa;font-size:0.85em;'>"
            for k, v in dados.items():
                if v:
                    dados_html += f"<li><b>{k}:</b> {v}</li>"
            dados_html += "</ul>"

        fontes_html += f"""
        <div style="border:1px solid #333;border-radius:6px;padding:12px;margin-bottom:10px;background:#0d1527;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:bold;color:#00e5ff;">{r['fonte']}</span>
                <span style="color:{cor_status};font-weight:bold;text-transform:uppercase;">{r['status']}</span>
            </div>
            <div style="color:#ccc;margin-top:6px;">{r.get('detalhe','—')}</div>
            {dados_html}
        </div>
        """

    # Bloco de TTPs
    ttps_html = ""
    if ttps:
        for ttp in ttps:
            taticas = ", ".join(ttp.get("taticas", [])) or "N/A"
            url_mitre = f"https://attack.mitre.org/techniques/{ttp['id'].replace('.', '/')}/"
            ttps_html += f"""
            <div style="border:1px solid #333;border-radius:6px;padding:10px;margin-bottom:8px;background:#0d1527;">
                <div>
                    <a href="{url_mitre}" target="_blank"
                       style="color:#00e5ff;font-weight:bold;text-decoration:none;">
                        {ttp['id']} — {ttp['nome']}
                    </a>
                </div>
                <div style="color:#888;font-size:0.85em;margin-top:4px;">Táticas: {taticas}</div>
                <div style="color:#aaa;font-size:0.82em;margin-top:4px;">
                    {ttp.get('descricao','')[:200]}{'...' if len(ttp.get('descricao','')) > 200 else ''}
                </div>
            </div>
            """
    else:
        ttps_html = "<p style='color:#666;'>Nenhuma TTP mapeada para este IOC.</p>"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Huginn — Relatório de Investigação</title>
<style>
  body {{ background:#0a0f1d; color:#e0e0e0; font-family:'Courier New',monospace; margin:0; padding:20px; }}
  .container {{ max-width:860px; margin:0 auto; }}
  .header {{ border-bottom:2px solid #00e5ff; padding-bottom:16px; margin-bottom:24px; }}
  .badge {{ display:inline-block; padding:6px 16px; border-radius:4px; font-weight:bold;
            font-size:1.1em; color:#0a0f1d; background:{cor}; }}
  .section-title {{ color:#00e5ff; font-size:1em; font-weight:bold; text-transform:uppercase;
                    letter-spacing:1px; margin:24px 0 12px 0; border-left:3px solid #00e5ff;
                    padding-left:10px; }}
  .meta {{ color:#888; font-size:0.85em; margin-top:8px; }}
  .ioc {{ font-size:1.3em; color:#ffffff; word-break:break-all; margin:8px 0; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:6px 10px; color:#ccc; font-size:0.9em; }}
  td:first-child {{ color:#00e5ff; width:140px; }}
  .footer {{ margin-top:32px; border-top:1px solid #222; padding-top:12px;
             color:#444; font-size:0.8em; text-align:center; }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div style="color:#00e5ff;font-size:0.9em;margin-bottom:8px;">
      🦅 HUGINN — Playbook de Investigação de IOC
    </div>
    <div class="ioc">{ioc}</div>
    <div style="margin-top:10px;">
      <span class="badge">{veredito}</span>
      <span style="color:#888;margin-left:12px;font-size:0.9em;">Score: {score}</span>
    </div>
    <div class="meta">
      Tipo: {tipo.upper()} &nbsp;|&nbsp; Gerado em: {agora}
    </div>
  </div>

  <div class="section-title">📋 Sumário Executivo</div>
  <table>
    <tr><td>IOC</td><td>{ioc}</td></tr>
    <tr><td>Tipo</td><td>{tipo.upper()}</td></tr>
    <tr><td>Veredito</td><td style="color:{cor};font-weight:bold;">{veredito}</td></tr>
    <tr><td>Score</td><td>{score}</td></tr>
    <tr><td>Fontes</td><td>{len(resultados)} consultadas</td></tr>
    <tr><td>TTPs</td><td>{len(ttps)} mapeadas</td></tr>
    <tr><td>Data/Hora</td><td>{agora}</td></tr>
  </table>

  <div class="section-title">🔍 Detalhes por Fonte</div>
  {fontes_html}

  <div class="section-title">🛡️ TTPs MITRE ATT&CK Relacionadas</div>
  {ttps_html}

  <div class="section-title">📌 Recomendações</div>
  <div style="background:#0d1527;border:1px solid #333;border-radius:6px;padding:14px;color:#ccc;">
    {"<ul style='margin:0;padding-left:20px;'><li>Bloquear o IOC imediatamente em firewalls e proxies.</li><li>Verificar logs internos por comunicação com este IOC nas últimas 72h.</li><li>Escalar para o time de resposta a incidentes se houver confirmação de comprometimento.</li><li>Documentar o incidente no sistema de ticketing com este relatório como evidência.</li></ul>" if "LIMPO" not in veredito else "<p style='margin:0;'>Nenhuma ação imediata necessária. Continuar monitoramento de rotina.</p>"}
  </div>

  <div class="footer">
    Gerado pelo Huginn — Playbook de Investigação de IOC &nbsp;|&nbsp;
    Dados fornecidos por fontes públicas de Threat Intelligence &nbsp;|&nbsp;
    MITRE ATT&amp;CK® é marca registrada da MITRE Corporation
  </div>

</div>
</body>
</html>"""

    return html
