# Hardening de Windows — Guía Completa

> Guía práctica de bastionado para sistemas Windows 10, Windows 11 y Windows Server 2019/2022. Cada sección contrarresta directamente las técnicas de ataque del módulo de Explotación.

---

## Tabla de contenidos

1. [Firewall de Windows](#1-firewall-de-windows)
2. [Windows Defender / Microsoft Defender](#2-windows-defender--microsoft-defender)
3. [UAC — Control de Cuentas de Usuario](#3-uac--control-de-cuentas-de-usuario)
4. [Políticas de contraseñas y cuentas](#4-políticas-de-contraseñas-y-cuentas)
5. [Desactivar protocolos peligrosos](#5-desactivar-protocolos-peligrosos)
6. [Macros de Office — Deshabilitar via GPO](#6-macros-de-office--deshabilitar-via-gpo)
7. [PowerShell — Restricciones y logging](#7-powershell--restricciones-y-logging)
8. [Actualizaciones de Windows](#8-actualizaciones-de-windows)
9. [BitLocker — Cifrado de disco](#9-bitlocker--cifrado-de-disco)
10. [Auditoría y monitorización (Sysmon)](#10-auditoría-y-monitorización-sysmon)
11. [Attack Surface Reduction (ASR)](#11-attack-surface-reduction-asr)
12. [Otros controles esenciales](#12-otros-controles-esenciales)
13. [Cheat Sheet de comandos](#13-cheat-sheet-de-comandos)

---

## 1. Firewall de Windows

El firewall es la **primera y más crítica línea de defensa**. Como se demostró en el módulo de Reconocimiento, un sistema sin firewall activo expone toda su arquitectura a cualquier escáner de red.

### Estado del firewall

```powershell
# Ver estado de todos los perfiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# Activar todos los perfiles de una vez
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Verificar
netsh advfirewall show allprofiles state
```

### Bloquear puertos críticos explotados habitualmente

```powershell
# ── SMB (EternalBlue, Pass-the-Hash) ──────────────────────────
New-NetFirewallRule -DisplayName "Bloquear SMB Entrada" `
    -Direction Inbound -Protocol TCP `
    -LocalPort 135,139,445 `
    -Action Block -Profile Any

# ── RDP (fuerza bruta, BlueKeep) ──────────────────────────────
# Si no necesitas RDP: bloquearlo
New-NetFirewallRule -DisplayName "Bloquear RDP Entrada" `
    -Direction Inbound -Protocol TCP `
    -LocalPort 3389 `
    -Action Block -Profile Any

# Si necesitas RDP: restringir solo a IPs de administración
New-NetFirewallRule -DisplayName "RDP solo admin" `
    -Direction Inbound -Protocol TCP `
    -LocalPort 3389 -RemoteAddress "192.168.1.10" `
    -Action Allow -Profile Domain

# ── WinRM (PowerShell remoto) ─────────────────────────────────
New-NetFirewallRule -DisplayName "Bloquear WinRM Entrada" `
    -Direction Inbound -Protocol TCP `
    -LocalPort 5985,5986 `
    -Action Block -Profile Public,Private

# ── Puertos de payload reverso habituales ─────────────────────
# (el tráfico saliente es más difícil de bloquear globalmente,
# pero sí se puede restringir con un proxy de salida o reglas por proceso)
```

### Verificar reglas activas

```powershell
# Ver todas las reglas de entrada habilitadas
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Select-Object DisplayName, Action, Profile |
    Sort-Object Action

# Ver reglas de un puerto específico
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Get-NetFirewallPortFilter |
    Where-Object {$_.LocalPort -eq 445}
```

### Política de denegación por defecto (avanzado)

```powershell
# Bloquear todo el tráfico entrante excepto lo explícitamente permitido
Set-NetFirewallProfile -Profile Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -NotifyOnListen True
```

---

## 2. Windows Defender / Microsoft Defender

### Verificar estado

```powershell
# Estado completo del antivirus
Get-MpComputerStatus | Select-Object `
    AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
    AntispywareEnabled, BehaviorMonitorEnabled,
    IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled,
    AntivirusSignatureLastUpdated, AMEngineVersion

# Estado simplificado
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled
```

### Habilitar todas las protecciones

```powershell
# Protección en tiempo real
Set-MpPreference -DisableRealtimeMonitoring $false

# Protección en la nube (envia muestras para análisis)
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Inspección de red
Set-MpPreference -DisableIOAVProtection $false

# Monitorización del comportamiento
Set-MpPreference -DisableBehaviorMonitoring $false

# Protección en acceso a scripts
Set-MpPreference -DisableScriptScanning $false

# Actualizar firmas ahora
Update-MpSignature
```

### AMSI — Anti-Malware Scan Interface

AMSI intercepta la ejecución de scripts (PowerShell, VBS, Office macros) y los analiza antes de ejecutarlos. Es la razón por la que muchos payloads de msfvenom son detectados.

```powershell
# Verificar que AMSI está activo (no hay un comando directo, pero sí indirectos)
# Si AMSI funciona, este test devuelve una detección:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | ForEach-Object {
    Write-Host "AMSI disponible: $($_ -ne $null)"
}
```

**Para el defensor:** AMSI debe estar activo. Los atacantes buscan bypass de AMSI como primer paso antes de ejecutar payloads en memoria.

---

## 3. UAC — Control de Cuentas de Usuario

### Niveles de UAC y cuál usar

```
Nivel 4 (máximo): Notificar siempre, escritorio seguro
→ Recomendado para usuarios estándar o entornos críticos

Nivel 3: Notificar cambios en apps, escritorio seguro
→ Recomendado para usuarios admin (equilibrio uso/seguridad)

Nivel 2: Notificar sin escritorio seguro
→ Vulnerable a bypass por inyección de DLL en el prompt

Nivel 1 (mínimo): Nunca notificar
→ UAC desactivado. NUNCA usar en producción
```

### Configurar UAC por PowerShell/Registro

```powershell
# Nivel 3 — recomendado (valor en el registro: 5)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 5

# Nivel 4 — máxima seguridad (valor: 2, con escritorio seguro)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "PromptOnSecureDesktop" -Value 1

# Verificar configuración actual
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, EnableLUA
```

---

## 4. Políticas de contraseñas y cuentas

### Configurar política de contraseñas (local)

```powershell
# Longitud mínima de contraseña: 14 caracteres
net accounts /minpwlen:14

# Historial de contraseñas: no repetir las últimas 24
net accounts /uniquepw:24

# Caducidad máxima: 90 días
net accounts /maxpwage:90

# Caducidad mínima: 1 día (evitar cambio inmediato para saltarse historial)
net accounts /minpwage:1

# Bloqueo de cuenta: 5 intentos fallidos, bloqueo 30 minutos
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

# Ver política actual
net accounts
```

### Deshabilitar cuentas peligrosas

```powershell
# Deshabilitar cuenta Guest
net user Guest /active:no
Disable-LocalUser -Name "Guest"

# Renombrar cuenta Administrador (oscurecer el objetivo)
Rename-LocalUser -Name "Administrador" -NewName "SysAdmin_Local"

# Ver usuarios locales con contraseña sin caducidad (riesgo)
Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} |
    Select-Object Name, Enabled, PasswordNeverExpires
```

---

## 5. Desactivar protocolos peligrosos

### SMBv1 — Vector de EternalBlue / WannaCry

SMBv1 es un protocolo de 1984 con vulnerabilidades críticas. No hay ningún motivo para tenerlo activo en sistemas modernos.

```powershell
# Verificar si SMBv1 está activo
Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Deshabilitar SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart

# Verificar
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
# → Debe ser: False
```

### LLMNR y NetBIOS — Vectores de Responder

LLMNR (Link-Local Multicast Name Resolution) y NetBIOS permiten ataques de envenenamiento de resolución de nombres (Responder) para capturar hashes NTLM.

```powershell
# Deshabilitar LLMNR via registro
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord

# Deshabilitar NetBIOS sobre TCP/IP (en cada interfaz)
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)   # 2 = Disabled
}

# Verificar LLMNR
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |
    Select-Object EnableMulticast
```

### Telnet — Protocolo sin cifrado

```powershell
# Comprobar si Telnet está instalado
Get-WindowsOptionalFeature -Online -FeatureName TelnetClient

# Desinstalar cliente Telnet si está instalado
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart

# Desactivar servicio Telnet server si existe
Stop-Service TlntSvr -ErrorAction SilentlyContinue
Set-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue
```

### Remote Registry — Acceso remoto al registro

```powershell
# Detener y deshabilitar el servicio Remote Registry
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled

# Verificar
Get-Service RemoteRegistry | Select-Object Name, Status, StartType
# → Debe ser: Stopped, Disabled
```

---

## 6. Macros de Office — Deshabilitar via GPO

Las macros VBA son el vector de infección más usado en campañas de phishing corporativo (como se demostró en el módulo de Explotación).

### Por registro (sin GPO)

```powershell
# Deshabilitar macros en Word, Excel y PowerPoint
$apps = @(
    "Word\Security",
    "Excel\Security",
    "PowerPoint\Security",
    "Access\Security"
)

foreach ($app in $apps) {
    $path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\$app"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }

    # VBAWarnings:
    # 1 = Habilitar todas (peligroso)
    # 2 = Deshabilitar con notificación
    # 3 = Deshabilitar excepto las firmadas digitalmente
    # 4 = Deshabilitar TODAS sin notificación (más seguro)
    Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4 -Type DWord
}

Write-Host "Macros VBA deshabilitadas en aplicaciones Office"
```

### Bloquear documentos de Internet (Mark of the Web)

```powershell
# Evitar que documentos descargados de internet activen macros
$path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security"
Set-ItemProperty -Path $path -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord
```

---

## 7. PowerShell — Restricciones y logging

PowerShell es una de las herramientas más usadas por atacantes post-explotación. Estas medidas dificultan su uso malicioso sin bloquearlo para administradores legítimos.

### ExecutionPolicy

```powershell
# Ver la política actual
Get-ExecutionPolicy -List

# Establecer política restrictiva (solo scripts firmados)
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Nivel de restricción para usuarios estándar
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
```

> **Nota:** ExecutionPolicy NO es un control de seguridad real — un atacante puede bypassearlo fácilmente con `-ExecutionPolicy Bypass`. El control real es el Script Block Logging y AMSI.

### Script Block Logging — El control más importante

Registra en el log de eventos de Windows todo el código PowerShell que se ejecuta, incluso si está ofuscado o en memoria.

```powershell
# Habilitar Script Block Logging
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Habilitar transcripción (guarda sesiones completas de PS en archivos)
$pathT = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $pathT)) { New-Item -Path $pathT -Force | Out-Null }
Set-ItemProperty -Path $pathT -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $pathT -Name "OutputDirectory" -Value "C:\PSlogs" -Type String

# Los logs aparecen en: Visor de Eventos →
# Aplicaciones y Servicios → Microsoft → Windows → PowerShell → Operational
# ID de Evento 4104 → Script Block ejecutado
```

### Constrained Language Mode (para entornos de alta seguridad)

```powershell
# Activar modo restringido de lenguaje (bloquea muchas técnicas de ofuscación)
# Solo funciona combinado con AppLocker o WDAC
[Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")
```

---

## 8. Actualizaciones de Windows

```powershell
# Verificar actualizaciones pendientes
Get-WindowsUpdate -ErrorAction SilentlyContinue

# Instalar todas las actualizaciones disponibles
Install-WindowsUpdate -AcceptAll -AutoReboot -ErrorAction SilentlyContinue

# Configurar actualizaciones automáticas (via registro)
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name "AUOptions"             -Value 4    # Descargar e instalar automáticamente
Set-ItemProperty -Path $path -Name "NoAutoUpdate"          -Value 0
Set-ItemProperty -Path $path -Name "ScheduledInstallDay"   -Value 0    # Cada día
Set-ItemProperty -Path $path -Name "ScheduledInstallTime"  -Value 3    # 03:00 AM

# Ver historial de actualizaciones instaladas
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

---

## 9. BitLocker — Cifrado de disco

Si el sistema se reinicia sin la clave de recuperación, el disco está protegido aunque se extraiga físicamente.

```powershell
# Ver estado de BitLocker en todas las unidades
Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage

# Activar BitLocker en la unidad del sistema (C:)
# Requiere TPM 1.2+ o contraseña de arranque
Enable-BitLocker -MountPoint "C:" `
    -EncryptionMethod XtsAes256 `
    -RecoveryPasswordProtector

# Guardar la clave de recuperación en un archivo (seguro)
$bl = Get-BitLockerVolume -MountPoint "C:"
$bl.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} |
    Select-Object RecoveryPassword |
    Out-File "C:\Users\Administrador\Desktop\BitLocker_RecoveryKey.txt"

# Ver estado de cifrado
manage-bde -status C:
```

---

## 10. Auditoría y monitorización (Sysmon)

**Sysmon** (System Monitor) de Sysinternals es la herramienta más potente para la detección de actividad maliciosa en Windows. Registra eventos que el log nativo de Windows no captura.

### Qué registra Sysmon

| Evento | ID | Descripción |
|--------|-----|-------------|
| Creación de proceso | 1 | Cada proceso nuevo con su hash |
| Conexión de red | 3 | Conexiones TCP/UDP por proceso |
| Modificación de registro | 13 | Cambios en claves clave (Run keys...) |
| Creación de archivos | 11 | Archivos nuevos en disco |
| Acceso al proceso | 10 | Inyección en otro proceso (Mimikatz) |
| Pipe nombrado | 17/18 | Canales que usa Meterpreter |

### Instalar Sysmon

```powershell
# 1. Descargar Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
# 2. Descargar config recomendada (SwiftOnSecurity):
# https://github.com/SwiftOnSecurity/sysmon-config

# 3. Instalar Sysmon con la configuración
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

# 4. Verificar que está corriendo
Get-Service Sysmon64

# Los logs aparecen en: Visor de Eventos →
# Aplicaciones y Servicios → Microsoft → Windows → Sysmon → Operational
```

### Políticas de auditoría de Windows

```powershell
# Habilitar auditoría de inicio de sesión (éxito y error)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Auditar creación de procesos
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Auditar cambios en el registro
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Auditar acceso a objetos del sistema
auditpol /set /subcategory:"Object Access" /success:enable /failure:enable

# Ver configuración actual
auditpol /get /category:*
```

---

## 11. Attack Surface Reduction (ASR)

Las reglas ASR son controles de Windows Defender que bloquean comportamientos específicos usados por malware, incluso si el antivirus no reconoce el archivo.

```powershell
# Verificar estado de las reglas ASR
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Habilitar reglas ASR clave (en modo Audit primero para ver el impacto)
# Modo: 0=Desactivado, 1=Bloquear, 2=Audit

# Bloquear macros de Office de crear procesos hijos
Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" `
                 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear Office de crear ejecutables
Add-MpPreference -AttackSurfaceReductionRules_Ids "3B576869-A4EC-4529-8536-B80A7769E899" `
                 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear scripts ofuscados
Add-MpPreference -AttackSurfaceReductionRules_Ids "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" `
                 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear llamadas a Win32 API desde macros de Office
Add-MpPreference -AttackSurfaceReductionRules_Ids "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" `
                 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear creación de procesos desde PSExec y WMI
Add-MpPreference -AttackSurfaceReductionRules_Ids "D1E49AAC-8F56-4280-B9BA-993A6D77406C" `
                 -AttackSurfaceReductionRules_Actions Enabled
```

---

## 12. Otros controles esenciales

### Deshabilitar RDP si no se usa

```powershell
# Deshabilitar RDP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 1

# Si se necesita RDP, habilitar NLA (Network Level Authentication)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1
```

### Deshabilitar Autorun en dispositivos USB

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
```

### LAPS — Local Administrator Password Solution

LAPS genera contraseñas únicas y aleatorias para la cuenta de administrador local en cada máquina del dominio, almacenadas en Active Directory.

```powershell
# Verificar si LAPS está instalado
Get-Module -ListAvailable | Where-Object {$_.Name -like "*LAPS*"}
Get-Command -Module AdmPwd.PS

# Si está en un dominio con LAPS
Get-AdmPwdPassword -ComputerName NombreEquipo
```

### Windows Defender Credential Guard

Protege los hashes NTLM y tickets Kerberos en memoria contra herramientas como Mimikatz.

```powershell
# Verificar si Credential Guard está activo
Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardSecurityServicesRunning

# Configurar vía Hyper-V (requiere hardware compatible)
# Mejor hacerlo desde: Panel de control → Características de Windows →
# → Hyper-V → Herramientas de seguridad basada en virtualización
```

---

## 13. Cheat Sheet de comandos

```
══════════════════════════════════════════════════════════════
           HARDENING WINDOWS — CHEAT SHEET
══════════════════════════════════════════════════════════════

FIREWALL
  Set-NetFirewallProfile -Profile * -Enabled True           Activar todos los perfiles
  New-NetFirewallRule -Direction Inbound -LocalPort 445 -Action Block   Bloquear puerto
  Get-NetFirewallProfile | Select Name, Enabled             Ver estado

DEFENDER
  Set-MpPreference -DisableRealtimeMonitoring $false        Protección en tiempo real
  Update-MpSignature                                        Actualizar firmas
  Get-MpComputerStatus | Select RealTimeProtectionEnabled

PROTOCOLOS PELIGROSOS
  Set-SmbServerConfiguration -EnableSMB1Protocol $false    Deshabilitar SMBv1
  Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled
  Disable-WindowsOptionalFeature -FeatureName TelnetClient  Quitar Telnet

POLÍTICAS
  net accounts /minpwlen:14 /uniquepw:24 /lockoutthreshold:5
  Disable-LocalUser -Name "Guest"

POWERSHELL LOGGING
  # Script Block Logging (ver sección 7)
  Set-ItemProperty "HKLM:\...\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

MACROS OFFICE
  # Ver sección 6 — clave VBAWarnings = 4

ACTUALIZACIONES
  Install-WindowsUpdate -AcceptAll -AutoReboot              Actualizar todo

SYSMON
  .\Sysmon64.exe -accepteula -i sysmonconfig.xml            Instalar
  Get-Service Sysmon64                                      Verificar

ASR (REGLAS MÁS IMPORTANTES)
  # Bloquear macros de Office creando procesos hijos
  Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB... -Actions Enabled

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [CIS Benchmark for Windows 11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baseline](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [INCIBE — Configuración segura de endpoints Windows](https://www.incibe.es/incibe-cert/blog/configuracion-de-seguridad-de-un-endpoint-windows)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Mitigations](https://attack.mitre.org/mitigations/enterprise/)
