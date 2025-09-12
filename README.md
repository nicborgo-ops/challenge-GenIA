# challenge-GenIA
# 🔎 Microservicio de Análisis de Logs con GenAI

Este script permite analizar archivos de logs (como `access.log` de Apache) utilizando modelos de lenguaje (LLM) como **OpenAI GPT-4o** o **Gemini Flash** para:

- Clasificar eventos como **críticos** o **informativos** con justificación
- Generar un **informe completo en Markdown**
- Crear un **CSV clasificando cada evento**
- Consultar reputación de IPs públicas (VirusTotal)

---

## 📦 Requisitos

- Python 3.9+
- API Key de [OpenAI](https://platform.openai.com/account/api-keys) o [Gemini](https://ai.google.dev/)
- API Key de [VirusTotal](https://virustotal.com) (opcional, pero recomendado)

---

## 🛠️ Instalación

```bash
git clone https://github.com/tuusuario/analizador-logs-genai.git
cd analizador-logs-genai
pip install -r requirements.txt
```

### Variables de entorno requeridas

```bash
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="..."  # Solo si vas a usar Gemini
export VT_API_KEY="..."      # Solo si querés reputación de IPs
```

---

## 🚀 Uso

```bash
python3 main.py \
  --input access.log \
  --outdir salida/ \
  --provider openai \
  --debug
```

### Parámetros

| Parámetro     | Descripción                                                   |
|---------------|----------------------------------------------------------------|
| `--input`     | Archivo `.log` a analizar                                     |
| `--outdir`    | Carpeta donde guardar los resultados                          |
| `--provider`  | LLM a usar: `openai` (por defecto) o `gemini`                 |
| `--skip-vt`   | Omitir consultas a VirusTotal                                 |
| `--debug`     | Mostrar mensajes de depuración                                |

---

## 🧾 Archivos generados

| Archivo                     | Descripción                                                        |
|-----------------------------|--------------------------------------------------------------------|
| `full_report.md`            | Informe completo en Markdown con clasificación, IOC, TTPs, etc.    |
| `classified_events.csv`     | CSV con severidad (`crítico` o `informativo`) y motivo por línea   |
| `vt_results.json` (opcional)| Resumen de reputación de IPs públicas consultadas a VirusTotal     |

---

## 📂 Ejemplo de salida (fragmento CSV)

```csv
line,severity,reason
1,informativo,Acceso GET a ruta estática común
2,crítico,Intento de acceso a /admin desde IP sospechosa
3,informativo,Petición favicon.ico desde IP interna
```

---

## 📌 Notas adicionales

- El script puede demorar si el archivo `.log` es muy grande o si hay muchas IPs públicas para consultar.
- Si usás `--skip-vt`, las IPs no serán analizadas por reputación.
- El informe generado en Markdown está listo para ser enviado a un CSIRT, CISO o documentación interna.

---

## 🤝 Contribuciones

¿Ideas, mejoras, bugs? ¡Abrí un issue o PR!

---

## 🛡️ Licencia

MIT – Usalo, adaptalo y mejoralo. Pero no lo uses para hacer maldades 😉.

## 🛡️ Mejoras futuras
- Integrar este script en un pipeline CI/CD de seguridad.  
- Conectar con un SIEM (Splunk/ELK) para ingesta automática.  
- Extender soporte a otros formatos de log (syslog, Windows Event Logs).  
- Generar reportes adicionales (ej: cumplimiento regulatorio).
- Mejorar la performance y costo.
