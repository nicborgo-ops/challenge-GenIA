#!/usr/bin/env python3
import os
import re
import json
import argparse
import requests
import yaml
import ipaddress
from typing import List, Dict, Any

# ---------------------------
# Utilidades
# ---------------------------
def debug(msg: str, enabled: bool = False):
    if enabled:
        print(f"[DEBUG] {msg}")

def is_public_ip(ip: str) -> bool:
    """Devuelve True si la IP es pública (ni privada, ni loopback, ni reservada)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
        )
    except ValueError:
        # Si la IP no es válida
        return False

def extract_ipv4s(text: str) -> List[str]:
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)

def clean_yaml_output(raw: str) -> str:
    """Elimina bloques de código tipo ```yaml ... ```"""
    if not raw:
        return ""
    cleaned = raw.strip()
    cleaned = re.sub(r"^```[a-zA-Z]*", "", cleaned)
    cleaned = re.sub(r"```$", "", cleaned)
    return cleaned.strip()

def fix_yaml_strings(raw: str) -> str:
    """Asegura que reason/explanation siempre estén entre comillas dobles completas."""
    fixed_lines = []
    for line in raw.splitlines():
        if line.strip().startswith(("reason:", "explanation:")):
            key, val = line.split(":", 1)
            val = val.strip()
            # Reemplazar comillas dobles internas por simples para no romper YAML
            val = val.replace('"', "'")
            # Forzar que empiece y termine con comillas dobles
            if not val.startswith('"'):
                val = '"' + val
            if not val.endswith('"'):
                val = val + '"'
            line = f"{key}: {val}"
        fixed_lines.append(line)
    return "\n".join(fixed_lines)

# ---------------------------
# Llamadas a LLM
# ---------------------------
def call_openai(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )
    return resp.choices[0].message.content

def call_gemini(prompt: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
    model = genai.GenerativeModel("gemini-1.5-flash")
    resp = model.generate_content(prompt)
    return resp.text

# ---------------------------
# Clasificación de eventos
# ---------------------------
def classify_all(events: List[Dict[str, Any]], provider: str, debug_enabled: bool = False) -> Dict[str, Any]:
    logs_text = ""
    for idx, e in enumerate(events, start=1):
        logs_text += f"{idx}: {e['raw'].strip()}\n"

    prompt = (
        "Analiza los logs numerados y asigna a CADA evento una clasificación de SEGURIDAD:\n"
        "- Usa \"crítico\" si el evento representa un riesgo real o contribuye a un ataque.\n"
        "- Usa \"informativo\" si es legítimo o de bajo riesgo.\n\n"
        "Devuelve SOLO un YAML válido con esta estructura (sin ``` ni bloques markdown):\n"
        "eventos:\n"
        "  - line: <int>\n"
        "    severity: \"crítico|informativo\"\n"
        "    reason: \"explicación breve, siempre entre comillas\"\n\n"
        "Notas IMPORTANTES:\n"
        "- Incluye absolutamente TODOS los eventos.\n"
        "- Usa los índices de línea provistos (1-based).\n"
        "- La clave severity es criticidad de seguridad, no el nivel de log.\n"
        "- Siempre provee una reason entre comillas.\n"
        "- Si un evento indica reverse shell, exfiltración, log tampering o comandos sospechosos, debe clasificarse como CRÍTICO.\n\n"
        '- Todos los valores de reason deben estar encerrados entre comillas dobles completas "...".'
        "- Nunca cortar la línea ni omitir la comilla de cierre."
        f"### Logs:\n{logs_text}"
    )

    debug(f"Llamando al LLM ({provider})...", debug_enabled)

    if provider == "openai":
        content = call_openai(prompt)
    else:
        content = call_gemini(prompt)

    debug(f"Raw LLM output (recortado): {content[:400]}...", debug_enabled)

    # limpiar y arreglar YAML
    content = clean_yaml_output(content)
    content = fix_yaml_strings(content)

    try:
        parsed = yaml.safe_load(content)
    except Exception as e:
        debug(f"Error parseando YAML: {e}", debug_enabled)
        return {"eventos": []}

    return parsed

# ---------------------------
# Reportes
# ---------------------------
def generate_reports(events: List[Dict[str, Any]], classifications: Dict[str, Any], vt_results: List[Dict[str, Any]], provider: str, debug_enabled: bool = False) -> Dict[str, str]:
    criticos = [e for e in classifications.get("eventos", []) if e["severity"] == "crítico"]

    metrics = {
        "total_eventos": len(events),
        "criticos": len(criticos),
        "informativos": len(events) - len(criticos),
    }

    vt_payload = [r for r in vt_results if not r.get("error")]

    prompt = (
        "Genera dos reportes distintos (CSIRT y CISO) en YAML con formato Markdown en los valores.\n\n"
        "Formato de salida:\n"
        "csirt_report: |\n"
        "  ## Reporte CSIRT\n"
        "  ### Timeline de Eventos Críticos\n"
        "  - Lista completa de TODOS los eventos críticos detectados. Cada línea debe incluir fecha/hora, IP, país (si disponible), ciudad (si disponible), organización (si disponible), usuario involucrado y explicación breve del porqué es crítico.\n"
        "  ### Tabla de TTPs\n"
        "  - Tabla en formato Markdown con columnas: TTP ID | Descripción | Actor asociado (si corresponde).\n"
        "  ### IOC Feed\n"
        "  - Listado completo de IPs, dominios, hashes, paths y comandos sospechosos detectados.\n"
        "  ### Estadísticas\n"
        "  - Totales de eventos, críticos, informativos, porcentaje de críticos.\n"
        "  ### Recomendaciones Inmediatas\n"
        "  - Lista de al menos 5 acciones concretas para el equipo CSIRT.\n"
        "  (No usar '...', no dejar secciones incompletas, no usar placeholders tipo [Recomendaciones]).\n\n"
        "ciso_report: |\n"
        "  ## Reporte CISO\n"
        "  - Narrativo ejecutivo en español, con un mínimo de 300 palabras.\n"
        "  - Debe cubrir: panorama general, actores principales, reputación y geolocalización de IPs relevantes, riesgos e impacto, nivel de riesgo global (0-100), acciones inmediatas y próximos pasos estratégicos.\n"
        "  (No usar '...', no resumir en exceso, no dejar secciones vacías).\n\n"
        "### Métricas:\n"
        f"{json.dumps(metrics, ensure_ascii=False)}\n\n"
        "### Eventos críticos (completos):\n"
        f"{json.dumps(criticos, ensure_ascii=False)}\n\n"
        "### Reputación de IPs:\n"
        f"{json.dumps(vt_payload, ensure_ascii=False)}\n\n"
        "Devuelve SOLO YAML válido, sin bloques de código ni backticks."
    )

    debug("Llamando al LLM para reportes...", debug_enabled)

    if provider == "openai":
        content = call_openai(prompt)
    else:
        content = call_gemini(prompt)

    debug(f"Raw LLM output (recortado): {content[:400]}...", debug_enabled)

    content = clean_yaml_output(content)
    try:
        parsed = yaml.safe_load(content)
    except Exception as e:
        debug(f"Error parseando YAML reportes: {e}", debug_enabled)
        return {"csirt_report": "", "ciso_report": ""}

    return parsed

# ---------------------------
# VirusTotal
# ---------------------------
def vt_lookup_ip(ip: str) -> Dict[str, Any]:
    apikey = os.environ.get("VT_API_KEY")
    if not apikey:
        return {"ip": ip, "error": "No API key VT"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": apikey}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return {"ip": ip, "data": r.json()}
    else:
        return {"ip": ip, "error": r.text}

# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Archivo .log a analizar")
    parser.add_argument("--outdir", required=True, help="Directorio de salida")
    parser.add_argument("--provider", choices=["openai", "gemini"], default="openai", help="Proveedor LLM")
    parser.add_argument("--skip-vt", action="store_true", help="Omitir consultas a VirusTotal")
    parser.add_argument("--debug", action="store_true", help="Habilitar modo debug")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()

    events = [{"line": idx, "raw": line.strip()} for idx, line in enumerate(lines, start=1)]

    classifications = classify_all(events, args.provider, args.debug)

    # VirusTotal
    vt_results = []
    if not args.skip_vt:
        ips_public = {ip for e in events for ip in extract_ipv4s(e["raw"]) if is_public_ip(ip)}
        vt_results = [vt_lookup_ip(ip) for ip in sorted(ips_public)]
        with open(os.path.join(args.outdir, "vt_results.json"), "w", encoding="utf-8") as f:
            json.dump(vt_results, f, indent=2, ensure_ascii=False)

    reports = generate_reports(events, classifications, vt_results, args.provider, args.debug)

    with open(os.path.join(args.outdir, "csirt_report.md"), "w", encoding="utf-8") as f:
        f.write(reports.get("csirt_report", "").strip() + "\n")

    with open(os.path.join(args.outdir, "ciso_report.md"), "w", encoding="utf-8") as f:
        f.write(reports.get("ciso_report", "").strip() + "\n")

    with open(os.path.join(args.outdir, "classified_events.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(classifications, f, indent=2, allow_unicode=True)

    print(f"📂 Artefactos generados en {args.outdir}/")

if __name__ == "__main__":
    main()
