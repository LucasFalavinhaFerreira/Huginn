"""
Dashboard Huginn — Playbook de Investigação de IOC.
"""
import gradio as gr
import tempfile
import os

from db import inicializar_banco, listar_investigacoes, buscar_investigacao
from investigator import investigar

inicializar_banco()
theme_base = gr.themes.Default()


def formatar_resultado_texto(resultado):
    linhas = [
        f"IOC: {resultado['ioc']}",
        f"Tipo: {resultado['tipo'].upper()}",
        f"Veredito: {resultado['veredito']} (score: {resultado['score']})",
        f"ID da investigação: #{resultado['id']}",
        "",
        "─── Resultados por Fonte ───",
    ]
    for r in resultado["resultados"]:
        emoji = {"malicioso": "🔴", "suspeito": "🟡", "limpo": "🟢", "erro": "⚠️"}.get(r["status"], "─")
        linhas.append(f"{emoji} {r['fonte']}: {r['detalhe']}")

    if resultado["ttps"]:
        linhas += ["", "─── TTPs MITRE ATT&CK Mapeadas ───"]
        for ttp in resultado["ttps"]:
            taticas = ", ".join(ttp.get("taticas", [])) or "N/A"
            linhas.append(f"• {ttp['id']} — {ttp['nome']} [{taticas}]")
    else:
        linhas += ["", "─── Nenhuma TTP mapeada ───"]

    return "\n".join(linhas)


def executar_investigacao(ioc):
    if not ioc or not ioc.strip():
        return "⚠️ Digite um IOC para investigar.", None, None
    try:
        resultado = investigar(ioc.strip())
        texto = formatar_resultado_texto(resultado)
        html = resultado["relatorio_html"]

        # Salva o HTML num arquivo temporário pra download
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False,
            prefix=f"huginn_{ioc.strip().replace('/','_')}_",
            encoding="utf-8"
        )
        tmp.write(html)
        tmp.close()

        return texto, html, tmp.name
    except Exception as e:
        return f"Erro na investigação: {str(e)}", None, None


def atualizar_historico():
    investigacoes = listar_investigacoes(limite=20)
    if not investigacoes:
        return "Nenhuma investigação realizada ainda."
    linhas = [f"{'ID':<6} {'Data':<20} {'Tipo':<10} {'Veredito':<20} {'IOC'}"]
    linhas.append("─" * 100)
    for inv in investigacoes:
        data = str(inv["data_investigacao"])[:16]
        linhas.append(
            f"#{inv['id']:<5} {data:<20} {inv['tipo']:<10} "
            f"{inv['veredito']:<20} {inv['ioc']}"
        )
    return "\n".join(linhas)


def carregar_investigacao_anterior(investigacao_id_str):
    try:
        inv_id = int(investigacao_id_str.strip().replace("#", ""))
        inv = buscar_investigacao(inv_id)
        if not inv:
            return "Investigação não encontrada.", None, None

        resultado_fake = {
            "id": inv["id"],
            "ioc": inv["ioc"],
            "tipo": inv["tipo"],
            "veredito": inv["veredito"],
            "score": inv["score"],
            "resultados": [
                {"fonte": k, "status": v["status"], "detalhe": v["detalhe"], "dados": v.get("dados", {})}
                for k, v in inv["detalhes_json"].items()
            ],
            "ttps": inv["ttps_json"],
        }
        texto = formatar_resultado_texto(resultado_fake)
        html = inv["relatorio_html"]

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False,
            prefix=f"huginn_historico_{inv_id}_",
            encoding="utf-8"
        )
        tmp.write(html)
        tmp.close()

        return texto, html, tmp.name
    except Exception as e:
        return f"Erro ao carregar investigação: {str(e)}", None, None


# ── Interface ──────────────────────────────────────────────────────────────

with gr.Blocks() as interface:
    gr.Markdown("🦅 Huginn — Playbook de Investigação de IOC | IP · Domínio · Hash")

    with gr.Tabs():

        # ── Aba 1: Investigar ──────────────────────────────────────────────
        with gr.Tab("🔎 Investigar IOC"):
            with gr.Row():
                with gr.Column(scale=1, elem_classes=["cyber-box"]):
                    gr.Markdown("### 🎯 IOC ALVO")
                    gr.Markdown(
                        "Cole um IOC pra investigar:\n"
                        "* **IP**: `1.2.3.4`\n"
                        "* **Domínio/URL**: `evil.com` ou `https://evil.com/phishing`\n"
                        "* **Hash**: MD5 (32 chars) ou SHA256 (64 chars)\n\n"
                        "O tipo é detectado automaticamente."
                    )
                    input_ioc = gr.Textbox(
                        label="IOC",
                        placeholder="IP, domínio, URL ou hash...",
                    )
                    btn_investigar = gr.Button("🦅 Iniciar Investigação", elem_classes=["neon-btn"])
                    btn_download = gr.File(label="📄 Download do Relatório HTML", interactive=False)

                    gr.Markdown(
                        "📊 Fontes:\n"
                        "* AbuseIPDB — reputação de IP\n"
                        "* VirusTotal — multi-engine\n"
                        "* URLhaus — malware distribution\n"
                        "* OpenPhish — phishing feed\n"
                        "* MalwareBazaar — hashes de malware\n"
                        "* MITRE ATT&CK — mapeamento de TTPs"
                    )

                with gr.Column(scale=2):
                    output_texto = gr.Textbox(
                        label="RESULTADO DA INVESTIGAÇÃO",
                        lines=20,
                        placeholder="Aguardando IOC...",
                        elem_classes=["terminal-console"],
                    )
                    output_html = gr.HTML(label="RELATÓRIO VISUAL")

            btn_investigar.click(
                fn=executar_investigacao,
                inputs=input_ioc,
                outputs=[output_texto, output_html, btn_download],
            )

        # ── Aba 2: Histórico ───────────────────────────────────────────────
        with gr.Tab("📋 Histórico (Muninn)"):
            gr.Markdown(
                "### 📋 MEMÓRIA DO CORVO (MUNINN)\n"
                "Todas as investigações ficam salvas. "
                "Digite o ID de uma investigação anterior pra recarregar o relatório completo."
            )
            with gr.Row():
                with gr.Column(scale=1, elem_classes=["cyber-box"]):
                    input_id = gr.Textbox(label="ID da investigação", placeholder="#42 ou 42")
                    btn_carregar = gr.Button("Carregar Investigação", elem_classes=["neon-btn"])
                    btn_download_hist = gr.File(label="📄 Download do Relatório", interactive=False)
                    btn_atualizar = gr.Button("Atualizar Lista", size="sm")

                with gr.Column(scale=2):
                    output_hist_lista = gr.Textbox(
                        label="INVESTIGAÇÕES ANTERIORES",
                        value=atualizar_historico(),
                        lines=10,
                        interactive=False,
                        elem_classes=["terminal-console"],
                    )
                    output_hist_texto = gr.Textbox(
                        label="DETALHES DA INVESTIGAÇÃO SELECIONADA",
                        lines=12,
                        interactive=False,
                        elem_classes=["terminal-console"],
                    )
                    output_hist_html = gr.HTML(label="RELATÓRIO VISUAL")

            btn_carregar.click(
                fn=carregar_investigacao_anterior,
                inputs=input_id,
                outputs=[output_hist_texto, output_hist_html, btn_download_hist],
            )
            btn_atualizar.click(
                fn=atualizar_historico,
                inputs=None,
                outputs=output_hist_lista,
            )

if __name__ == "__main__":
    interface.queue()
    interface.launch(theme=theme_base, css="style.css")
