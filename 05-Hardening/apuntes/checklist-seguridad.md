# Checklist de Seguridad

> Listas de verificación para dos contextos: **baseline de hardening** (estado que debe tener un sistema seguro) y **ciclo de auditoría** (antes, durante y después de un pentest).

---

## Parte 1 — Baseline de Seguridad del Sistema

Marca cada ítem cuando esté correctamente configurado. Usa `hardening_audit.ps1` para automatizar las verificaciones.

---

### 🔥 Firewall y Red

- [ ] **Firewall activo en los tres perfiles** (Domain, Private, Public)
- [ ] **Puerto 445 (SMB) bloqueado** en el firewall de entrada si no se usa activamente
- [ ] **Puerto 135 (MSRPC) bloqueado** en el firewall de entrada
- [ ] **Puerto 139 (NetBIOS) bloqueado** en el firewall de entrada
- [ ] **Puerto 3389 (RDP) bloqueado** o restringido a IPs de administración
- [ ] **Puerto 5985/5986 (WinRM) bloqueado** o restringido
- [ ] **SMBv1 desactivado** (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`)
- [ ] **LLMNR desactivado** (previene ataques Responder)
- [ ] **NetBIOS sobre TCP/IP desactivado** en todas las interfaces
- [ ] **Telnet no instalado** o servicio desactivado
- [ ] **Remote Registry desactivado** (servicio `RemoteRegistry` en estado Disabled)

---

### 🛡️ Antivirus y Detección

- [ ] **Windows Defender activo** y actualizado (o solución EDR equivalente)
- [ ] **Protección en tiempo real habilitada**
- [ ] **Protección en la nube habilitada** (MAPS en Advanced)
- [ ] **Firmas de malware actualizadas** (menos de 24h de antigüedad)
- [ ] **AMSI activo** (no deshabilitado por políticas)
- [ ] **ASR activo** con reglas mínimas:
  - [ ] Bloquear macros de Office de crear procesos hijos
  - [ ] Bloquear Office de crear ejecutables
  - [ ] Bloquear scripts ofuscados
- [ ] **Sysmon instalado** con configuración actualizada

---

### 🔑 Autenticación y Cuentas

- [ ] **Contraseña mínima: 14 caracteres**
- [ ] **Historial de contraseñas: 24 anteriores** (evitar reutilización)
- [ ] **Caducidad máxima: 90 días** (o menos en entornos críticos)
- [ ] **Bloqueo de cuenta: 5 intentos** → bloqueo 30 min
- [ ] **Cuenta Guest desactivada**
- [ ] **Cuenta Administrador renombrada** (no usar el nombre por defecto)
- [ ] **Sin cuentas con contraseña que nunca caduca** (salvo cuentas de servicio documentadas)
- [ ] **MFA habilitado** para cuentas administrativas
- [ ] **LAPS configurado** en entornos de dominio (contraseñas únicas por equipo)
- [ ] **Sin cuentas de usuario compartidas** entre varias personas

---

### ⚙️ Sistema Operativo

- [ ] **Sistema operativo actualizado** (todos los parches de seguridad aplicados)
- [ ] **UAC en nivel 3 o 4** (no desactivado)
- [ ] **BitLocker activo** en la unidad del sistema con clave de recuperación guardada
- [ ] **Credential Guard activo** (si el hardware lo soporta)
- [ ] **Autorun desactivado** para dispositivos USB y medios extraíbles
- [ ] **RDP desactivado** si no se usa, o con NLA habilitado si es necesario
- [ ] **No hay software innecesario instalado** (reducir superficie de ataque)

---

### 📝 Office y Documentos

- [ ] **Macros VBA deshabilitadas** en Word, Excel, PowerPoint y Access
- [ ] **Documentos de Internet bloqueados** para ejecutar contenido activo
- [ ] **Protected View activo** para documentos de origen externo
- [ ] **Sin macros de orígenes no de confianza permitidas**

---

### 💻 PowerShell

- [ ] **Script Block Logging habilitado** (Event ID 4104)
- [ ] **Transcripción de PowerShell habilitada** con logs en ruta protegida
- [ ] **ExecutionPolicy en AllSigned** o superior para administradores
- [ ] **ExecutionPolicy en Restricted** para usuarios estándar

---

### 📊 Logging y Monitorización

- [ ] **Auditoría de inicio de sesión activada** (éxito y fracaso)
- [ ] **Auditoría de creación de procesos activada**
- [ ] **Auditoría de cambios en el registro activada**
- [ ] **Logs de Windows centralizados** en SIEM (Splunk, ELK, Wazuh...)
- [ ] **Alertas configuradas** para eventos críticos:
  - [ ] Múltiples fallos de login (ID 4625) → posible fuerza bruta
  - [ ] Borrado de logs (ID 1102) → posible actividad maliciosa
  - [ ] Nuevo servicio instalado (ID 7045)
  - [ ] Cambio en grupos de administradores (ID 4728, 4732)
  - [ ] Inicio de sesión fuera del horario habitual

---

## Parte 2 — Ciclo de Auditoría (Red Team)

---

### ✅ Antes de la auditoría

**Aspectos legales y organizativos:**
- [ ] **Contrato de auditoría firmado** por el propietario del sistema
- [ ] **Scope definido y documentado**: IPs, rangos, sistemas, horarios
- [ ] **Contacto de emergencia del cliente** disponible (para parar si hay un incidente)
- [ ] **Aprobación de firewall** y excepciones necesarias documentadas
- [ ] **Notificación al SOC/equipo de seguridad** del cliente (si aplica)
- [ ] **Ventana de tiempo aprobada** para las pruebas intrusivas

**Preparación técnica:**
- [ ] Kali Linux actualizado (`sudo apt update && sudo apt upgrade`)
- [ ] Metasploit actualizado (`msfupdate`)
- [ ] Nmap actualizado
- [ ] VPN o acceso de red configurado correctamente
- [ ] Máquina atacante con IP en el rango autorizado
- [ ] `.gitignore` configurado para no subir resultados sensibles
- [ ] Directorio de trabajo creado para la auditoría (`/root/audit_cliente_FECHA/`)

---

### 🔍 Durante la auditoría

**Fase de Reconocimiento:**
- [ ] Ping sweep del segmento autorizado (`nmap -sn`)
- [ ] Fingerprinting de hosts descubiertos (`nmap -sV -sC -O -Pn`)
- [ ] Documentar todos los hosts, puertos y servicios encontrados
- [ ] Buscar CVEs para los servicios identificados (`vuln_checker.py`)

**Fase de Explotación:**
- [ ] Verificar si el exploit funciona antes de lanzar (`check`)
- [ ] Anotar el timestamp exacto de cada acción (para el informe)
- [ ] Guardar capturas de pantalla de evidencias
- [ ] No lanzar exploits que puedan causar DoS (indisponibilidad) sin autorización

**Fase de Post-Explotación:**
- [ ] Documentar el usuario obtenido y el nivel de privilegios
- [ ] Registrar todas las rutas de escalada utilizadas
- [ ] Guardar evidencias de acceso a activos críticos (capturas)
- [ ] Documentar hosts internos adicionales descubiertos (pivoting)
- [ ] NO exfiltrar datos reales del cliente (usar archivos de prueba/flags)
- [ ] Anotar todos los mecanismos de persistencia instalados

---

### 🧹 Después de la auditoría — Limpieza

> Este paso es **obligatorio** en toda auditoría profesional. El sistema debe quedar exactamente igual que al inicio.

**Eliminar payloads y herramientas:**
- [ ] Eliminar todos los ejecutables subidos al sistema (`payload.exe`, `winPEASx64.exe`...)
- [ ] Eliminar todos los scripts subidos (`.py`, `.ps1`, `.bat`...)
- [ ] Eliminar archivos temporales creados durante las pruebas

**Eliminar persistencia:**
- [ ] Eliminar entradas de Run Keys maliciosas del registro
  ```powershell
  reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "NombreMalicioso" /f
  ```
- [ ] Eliminar tareas programadas creadas
  ```powershell
  schtasks /delete /tn "NombreTarea" /f
  ```
- [ ] Eliminar servicios creados
  ```powershell
  sc stop "NombreServicio"; sc delete "NombreServicio"
  ```
- [ ] Eliminar suscripciones WMI maliciosas
- [ ] Verificar con **Autoruns** (Sysinternals) que no queda nada

**Restaurar configuración:**
- [ ] Restaurar la configuración de seguridad que se desactivó para las pruebas
  - [ ] Reactivar Windows Defender
  - [ ] Reactivar Firewall
  - [ ] Restaurar UAC al nivel original
- [ ] Verificar que los servicios críticos siguen funcionando

**Verificación final:**
- [ ] Ejecutar `hardening_audit.ps1` para confirmar que el sistema está en el estado esperado
- [ ] Revisar los logs de eventos para asegurar que las evidencias del ataque son correctas
- [ ] Confirmar con el cliente que todos los sistemas funcionan con normalidad

---

### 📋 Informe de Auditoría

- [ ] **Resumen ejecutivo** (para dirección, sin tecnicismos)
- [ ] **Metodología** utilizada (PTES, OWASP, PETA...)
- [ ] **Hallazgos** ordenados por severidad (CVSS o similares)
- [ ] **Evidencias** (capturas de pantalla, logs, comandos usados)
- [ ] **Impacto** de cada hallazgo (qué podría haber hecho un atacante real)
- [ ] **Recomendaciones** concretas y priorizadas para cada hallazgo
- [ ] **Plan de remediación** con plazos sugeridos
- [ ] **Verificación de remediación** (si se incluye retesting)

---

## Parte 3 — Eventos de Windows clave para el Blue Team

| ID Evento | Descripción | Cuándo alertar |
|-----------|-------------|----------------|
| **4624** | Inicio de sesión exitoso | Fuera de horario, desde IP inusual |
| **4625** | Inicio de sesión fallido | Más de 5 en 1 minuto (fuerza bruta) |
| **4648** | Login con credenciales explícitas (runas) | Siempre revisar |
| **4688** | Creación de proceso | Procesos inusuales: cmd, ps, mshta... |
| **4698** | Tarea programada creada | Siempre revisar |
| **4720** | Cuenta de usuario creada | Siempre revisar |
| **4732** | Usuario añadido a grupo Admin | Siempre alertar |
| **7045** | Servicio nuevo instalado | Siempre revisar |
| **1102** | Log de seguridad borrado | 🚨 Alerta crítica |
| **4104** | Script PowerShell ejecutado | Revisar si contiene comandos sospechosos |
| **Sysmon 1** | Proceso creado (con hash) | Correlacionar con threat intel |
| **Sysmon 3** | Conexión de red por proceso | Word/Excel haciendo conexiones salientes 🚨 |
| **Sysmon 13** | Modificación de registro | Claves Run, Winlogon, Services |

---

## Referencias

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES — Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [Sysinternals Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
