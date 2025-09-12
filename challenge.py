#!/usr/bin/env python3
import os
import re
import json
import argparse
import requests
import ipaddress
from typing import List, Dict, Any

# ---------------------------
# Utilidades
# ---------------------------
def debug(msg: str, enabled: bool = False):
    if enabled:
        print(f"[DEBUG] {msg}")

def is_public_ip(ip: str) -> bool:
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
        return False

def extract_ipv4s(text: str) -> List[str]:
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)

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
# Informe completo en Markdown
# ---------------------------
def classify_and_report(events: List[Dict[str, Any]], vt_results: List[Dict[str, Any]], provider: str, debug_enabled: bool = False) -> str:
    logs_text = "".join(f"{idx}: {e['raw'].strip()}\n" for idx, e in enumerate(events, start=1))
    vt_payload = [r for r in vt_results if not r.get("error")]

    prompt = (
        "Actuá como un analista de ciberseguridad experto en detección de incidentes y análisis de logs HTTP.\n"
        "Tu tarea es analizar los siguientes logs y generar un **único informe en formato Markdown**, claro y completo.\n\n"
        "## 🎯 Objetivo\n"
        "Clasificá cada evento como **'crítico'** o **'informativo'** no solo por su apariencia, sino por su **contexto dentro de una posible cadena de ataque**, teniendo en cuenta:\n"
        "- Intentos de acceso a rutas sensibles (/admin, /login, /wp-admin, etc.)\n"
        "- Descarga o ejecución de archivos (`.sh`, `.php`, `.zip`, `.exe`, etc.)\n"
        "- Uso de herramientas como curl, wget o agentes sospechosos\n"
        "- Solicitudes automatizadas, repetitivas o fuera de horario\n"
        "- IPs con mala reputación, según el objeto proporcionado (VirusTotal u otras)\n"
        "- Indicadores relacionados con técnicas del framework MITRE ATT&CK (por ejemplo: T1059, T1105, T1566)\n"
        "- Actividad que pueda suponer exploración, explotación, persistencia o exfiltración\n\n"
        "## 🧾 Estructura del informe (Markdown, sin bloques de código ni JSON):\n"
        "1. **📝 Resumen Ejecutivo** (200 palabras aprox.) — Debe contextualizar lo que ocurrió, los riesgos principales y sugerir medidas prioritarias.\n"
        "2. **⏱ Timeline de eventos críticos** — Una línea por evento crítico detectado. Incluir:\n"
        "   - Fecha y hora\n"
        "   - Evento completo (raw log)\n"
        "   - Breve motivo por el cual fue clasificado como crítico\n"
        "3. **🧠 Tabla de TTPs MITRE observadas** — Si se detectan, listá: ID, nombre, fase del ataque.\n"
        "4. **📦 IOC Feed** — IPs, dominios, hashes, rutas o comandos maliciosos, listos para usar en SIEM, WAF o EDR.\n"
        "5. **📊 Estadísticas generales** — Totales de eventos, cuántos críticos/informativos, y % de criticidad.\n"
        "6. **🛠 Recomendaciones inmediatas** — Al menos 5 acciones técnicas sugeridas para mitigar, investigar o escalar el incidente.\n\n"
        "## 📂 Datos a analizar:\n"
        f"- Logs:\n{logs_text}\n\n"
        f"- Reputación de IPs (VirusTotal, abuseIPDB, etc.):\n{json.dumps(vt_payload, ensure_ascii=False)}\n\n"
        "🚫 Devuelve **solo el informe final en formato Markdown**. No incluyas JSON ni bloques de código."
    )
    debug("Llamando al LLM para informe en 1 sola pasada...", debug_enabled)

    if provider == "openai":
        return call_openai(prompt)
    else:
        return call_gemini(prompt)

# ---------------------------
# Clasificación en CSV
# ---------------------------
def classify_to_csv(events: List[Dict[str, Any]], provider: str, debug_enabled: bool = False) -> str:
    logs_text = "".join(f"{idx}: {e['raw'].strip()}\n" for idx, e in enumerate(events, start=1))

    prompt = (
        "Actuá como un analista de ciberseguridad experto en detección de amenazas y análisis de logs.\n"
        "Tu tarea es revisar los siguientes logs y clasificarlos uno por uno según su nivel de severidad, teniendo en cuenta el **contexto de seguridad**.\n\n"
        "## 🎯 Instrucciones de clasificación:\n"
        "- Clasificá cada línea como:\n"
        "  • 'crítico' si representa o forma parte de un posible incidente (ej: intento de intrusión, escaneo, exfiltración, descarga de malware, uso de herramientas automatizadas, rutas sensibles, IP maliciosa, comportamiento anómalo, etc.).\n"
        "  • 'informativo' si es un evento normal o esperado sin riesgo.\n"
        "- No te limites a palabras clave: evaluá el comportamiento, frecuencia, patrón, y reputación de IPs si están disponibles.\n"
        "- Incluir todos los eventos sin omitir ninguno.\n\n"
        "## 📤 Formato de salida:\n"
        "- Salida en **formato CSV sin cabecera extra**.\n"
        "- Columnas:\n"
        "  • `line` (número de línea, comenzando desde 1)\n"
        "  • `severity` ('crítico' o 'informativo')\n"
        "  • `reason` (explicación breve y clara del motivo de la clasificación)\n"
        "- El CSV debe ser limpio, sin encabezados duplicados, sin texto adicional, sin bloques de código.\n\n"
        f"### Logs:\n{logs_text}\n\n"
        "Devuelve SOLO el contenido del archivo CSV, sin envoltorios, sin comentarios, sin bloques de código."
    )
    debug("Llamando al LLM para clasificación en CSV...", debug_enabled)

    if provider == "openai":
        return call_openai(prompt)
    else:
        return call_gemini(prompt)

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

    vt_results = []
    if not args.skip_vt:
        ips_public = {ip for e in events for ip in extract_ipv4s(e["raw"]) if is_public_ip(ip)}
        vt_results = [vt_lookup_ip(ip) for ip in sorted(ips_public)]
        with open(os.path.join(args.outdir, "vt_results.json"), "w", encoding="utf-8") as f:
            json.dump(vt_results, f, indent=2, ensure_ascii=False)

    # Informe en Markdown
    report = classify_and_report(events, vt_results, args.provider, args.debug)
    with open(os.path.join(args.outdir, "full_report.md"), "w", encoding="utf-8") as f:
        f.write(report.strip() + "\n")

    # Clasificación en CSV
    csv_result = classify_to_csv(events, args.provider, args.debug)
    with open(os.path.join(args.outdir, "classified_events.csv"), "w", encoding="utf-8") as f:
        f.write(csv_result.strip() + "\n")

    print(f"📂 Artefactos generados en {args.outdir}/")

if __name__ == "__main__":
    main()
