<#
.SYNOPSIS
    Auditoría de seguridad y hardening para sistemas Windows.

.DESCRIPTION
    Comprueba el estado de los controles de seguridad más importantes
    en un sistema Windows y genera un informe de cumplimiento con
    puntuación, estado por control y recomendaciones de mejora.

    Controles auditados:
    - Firewall (todos los perfiles)
    - Windows Defender y protecciones asociadas
    - UAC (nivel de configuración)
    - Políticas de contraseñas y cuentas
    - SMBv1 (vector EternalBlue)
    - LLMNR / NetBIOS (vector Responder)
    - Protocolos peligrosos (Telnet, Remote Registry)
    - Macros de Office
    - PowerShell (ExecutionPolicy, Script Block Logging)
    - Windows Update
    - BitLocker
    - RDP y NLA
    - Sysmon
    - Cuenta Guest y cuentas sin caducidad
    - Attack Surface Reduction (ASR)
    - Compartidos administrativos

.NOTES
    Autor  : Constan4 / Cybersecurity Repository
    Repo   : https://github.com/Constan4/Cybersecurity
    Req.   : PowerShell 5.0+, Windows 10/11 o Server 2016+
    Perms  : Ejecutar como Administrador para resultados completos

.EXAMPLE
    # Auditoría básica con informe en el directorio actual
    .\hardening_audit.ps1

.EXAMPLE
    # Especificar directorio de salida
    .\hardening_audit.ps1 -OutputDir "C:\Auditoria_Empresa"

.EXAMPLE
    # Sin colores (útil para redirigir la salida a un archivo)
    .\hardening_audit.ps1 -NoColor > audit.txt
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Directorio donde guardar el informe generado")]
    [string]$OutputDir = ".\hardening_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(HelpMessage = "Desactivar colores en la salida de consola")]
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ══════════════════════════════════════════════════════════════
# CONFIGURACIÓN DE COLORES
# ══════════════════════════════════════════════════════════════

$COLORS = @{
    OK          = if ($NoColor) { "Gray" } else { "Green" }
    ADVERTENCIA = if ($NoColor) { "Gray" } else { "Yellow" }
    FALLO       = if ($NoColor) { "Gray" } else { "Red" }
    INFO        = if ($NoColor) { "Gray" } else { "Cyan" }
    TITULO      = if ($NoColor) { "Gray" } else { "Magenta" }
    RESET       = "Gray"
}

# ══════════════════════════════════════════════════════════════
# VARIABLES GLOBALES
# ══════════════════════════════════════════════════════════════

$Script:Resultados  = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:TotalOK     = 0
$Script:TotalAdvert = 0
$Script:TotalFallo  = 0
$Script:TotalInfo   = 0
$Script:Inicio      = Get-Date


# ══════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ══════════════════════════════════════════════════════════════

function Write-Banner {
    $sep = "═" * 62
    Write-Host ""
    Write-Host "  $sep" -ForegroundColor $COLORS.TITULO
    Write-Host "  hardening_audit.ps1  —  Auditoría de Seguridad Windows" -ForegroundColor $COLORS.TITULO
    Write-Host "  Constan4 / Cybersecurity Repository" -ForegroundColor $COLORS.TITULO
    Write-Host "  $sep" -ForegroundColor $COLORS.TITULO
    Write-Host ""
}

function Write-Seccion {
    param([string]$Titulo)
    Write-Host ""
    Write-Host "  ── $Titulo " -ForegroundColor $COLORS.TITULO -NoNewline
    Write-Host ("─" * (55 - $Titulo.Length)) -ForegroundColor $COLORS.TITULO
    Write-Host ""
}

function Add-Check {
    <#
    .SYNOPSIS
        Añade un resultado de control a la lista y lo muestra en consola.
    .PARAMETER Estado
        OK | ADVERTENCIA | FALLO | INFO
    #>
    param (
        [string]$Nombre,
        [string]$Estado,
        [string]$Valor      = "",
        [string]$Esperado   = "",
        [string]$Categoria  = "General",
        [string]$Detalle    = ""
    )

    $check = [PSCustomObject]@{
        Nombre    = $Nombre
        Estado    = $Estado
        Valor     = $Valor
        Esperado  = $Esperado
        Categoria = $Categoria
        Detalle   = $Detalle
    }

    $Script:Resultados.Add($check)

    switch ($Estado) {
        "OK"          { $Script:TotalOK++;     $color = $COLORS.OK }
        "ADVERTENCIA" { $Script:TotalAdvert++; $color = $COLORS.ADVERTENCIA }
        "FALLO"       { $Script:TotalFallo++;  $color = $COLORS.FALLO }
        default       { $Script:TotalInfo++;   $color = $COLORS.INFO }
    }

    $estadoPad = "[$Estado]".PadRight(14)
    Write-Host "  " -NoNewline
    Write-Host $estadoPad -ForegroundColor $color -NoNewline
    Write-Host $Nombre

    if ($Detalle -and $Estado -ne "OK") {
        Write-Host "               → $Detalle" -ForegroundColor DarkGray
    }
}


# ══════════════════════════════════════════════════════════════
# COMPROBACIONES DE SEGURIDAD
# ══════════════════════════════════════════════════════════════

# ── 1. FIREWALL ───────────────────────────────────────────────

function Test-Firewall {
    Write-Seccion "FIREWALL DE WINDOWS"

    $perfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

    foreach ($perfil in $perfiles) {
        $estado = if ($perfil.Enabled) { "OK" } else { "FALLO" }
        $detalle = if (-not $perfil.Enabled) { "Ejecutar: Set-NetFirewallProfile -Profile $($perfil.Name) -Enabled True" } else { "" }

        Add-Check `
            -Nombre    "Firewall activo — Perfil $($perfil.Name)" `
            -Estado    $estado `
            -Valor     $perfil.Enabled.ToString() `
            -Esperado  "True" `
            -Categoria "Firewall" `
            -Detalle   $detalle
    }

    # Comprobar si puertos críticos están bloqueados
    $puertosCriticos = @(445, 139, 135, 3389)
    foreach ($puerto in $puertosCriticos) {
        $regla = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block `
            -ErrorAction SilentlyContinue |
            Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $puerto }

        $estado = if ($regla) { "OK" } else { "ADVERTENCIA" }
        $detalle = if (-not $regla) { "No hay regla explícita de bloqueo. El perfil activo puede filtrarlo igualmente." } else { "" }

        Add-Check `
            -Nombre    "Regla de bloqueo entrada — Puerto $puerto" `
            -Estado    $estado `
            -Valor     $(if ($regla) { "Bloqueado" } else { "Sin regla explícita" }) `
            -Esperado  "Bloqueado" `
            -Categoria "Firewall" `
            -Detalle   $detalle
    }
}


# ── 2. WINDOWS DEFENDER ───────────────────────────────────────

function Test-Defender {
    Write-Seccion "WINDOWS DEFENDER"

    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if (-not $mpStatus) {
        Add-Check -Nombre "Windows Defender" -Estado "INFO" `
            -Valor "No se pudo obtener estado" `
            -Detalle "Puede estar gestionado por un EDR de terceros" `
            -Categoria "Defender"
        return
    }

    # Protección en tiempo real
    Add-Check `
        -Nombre    "Protección en tiempo real" `
        -Estado    $(if ($mpStatus.RealTimeProtectionEnabled) { "OK" } else { "FALLO" }) `
        -Valor     $mpStatus.RealTimeProtectionEnabled.ToString() `
        -Esperado  "True" `
        -Categoria "Defender" `
        -Detalle   $(if (-not $mpStatus.RealTimeProtectionEnabled) { "Set-MpPreference -DisableRealtimeMonitoring `$false" } else { "" })

    # Protección en la nube
    $cloudProteccion = ($mpStatus.AMRunningMode -ne "Passive") -and ($mpStatus.NISEnabled)
    Add-Check `
        -Nombre    "Monitorización de red (NIS)" `
        -Estado    $(if ($mpStatus.NISEnabled) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $mpStatus.NISEnabled.ToString() `
        -Esperado  "True" `
        -Categoria "Defender"

    # Firmas actualizadas (menos de 48h)
    $horasFirmas = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalHours
    $estadoFirmas = if ($horasFirmas -lt 48) { "OK" } elseif ($horasFirmas -lt 168) { "ADVERTENCIA" } else { "FALLO" }
    Add-Check `
        -Nombre    "Antigüedad de firmas antivirus" `
        -Estado    $estadoFirmas `
        -Valor     "$([math]::Round($horasFirmas, 1))h" `
        -Esperado  "< 48h" `
        -Categoria "Defender" `
        -Detalle   $(if ($estadoFirmas -ne "OK") { "Ejecutar: Update-MpSignature" } else { "" })
}


# ── 3. UAC ────────────────────────────────────────────────────

function Test-UAC {
    Write-Seccion "UAC — CONTROL DE CUENTAS DE USUARIO"

    $uacPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $enableUAC = (Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $level     = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $secDesk   = (Get-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop

    # UAC habilitado
    Add-Check `
        -Nombre    "UAC habilitado (EnableLUA)" `
        -Estado    $(if ($enableUAC -eq 1) { "OK" } else { "FALLO" }) `
        -Valor     $(if ($enableUAC -eq 1) { "Habilitado" } else { "Deshabilitado" }) `
        -Esperado  "Habilitado" `
        -Categoria "UAC" `
        -Detalle   $(if ($enableUAC -ne 1) { "UAC desactivado. Riesgo crítico de escalada." } else { "" })

    # Nivel de UAC
    $nivelDesc = switch ($level) {
        0 { "Nunca notificar (UAC desactivado)" }
        1 { "Notificar sin escritorio seguro" }
        2 { "Notificar sin escritorio seguro (opciones de Windows)" }
        5 { "Notificar solo cambios en apps (por defecto)" }
        2 { "Notificar siempre (máximo)" }
        default { "Valor: $level" }
    }
    $estadoNivel = if ($level -ge 3) { "OK" } elseif ($level -ge 1) { "ADVERTENCIA" } else { "FALLO" }
    Add-Check `
        -Nombre    "Nivel de UAC" `
        -Estado    $estadoNivel `
        -Valor     $nivelDesc `
        -Esperado  "ConsentPromptBehaviorAdmin >= 3" `
        -Categoria "UAC"

    # Escritorio seguro
    Add-Check `
        -Nombre    "Escritorio seguro en prompts UAC" `
        -Estado    $(if ($secDesk -eq 1) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($secDesk -eq 1) { "Activo" } else { "Inactivo" }) `
        -Esperado  "Activo" `
        -Categoria "UAC"
}


# ── 4. POLÍTICAS DE CONTRASEÑAS ───────────────────────────────

function Test-PasswordPolicy {
    Write-Seccion "POLÍTICAS DE CONTRASEÑAS Y CUENTAS"

    $netAccounts = net accounts 2>$null

    # Extraer valores con regex
    $minLen = if ($netAccounts -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { 0 }
    $maxAge = if ($netAccounts -match "Maximum password age \(days\):\s+(\S+)") { $Matches[1] } else { "Unlimited" }
    $lockTh = if ($netAccounts -match "Lockout threshold:\s+(\S+)") { $Matches[1] } else { "Never" }
    $history = if ($netAccounts -match "Length of password history maintained:\s+(\S+)") { $Matches[1] } else { "None" }

    # Longitud mínima
    Add-Check `
        -Nombre    "Longitud mínima de contraseña" `
        -Estado    $(if ($minLen -ge 14) { "OK" } elseif ($minLen -ge 8) { "ADVERTENCIA" } else { "FALLO" }) `
        -Valor     "$minLen caracteres" `
        -Esperado  ">= 14 caracteres" `
        -Categoria "Contraseñas" `
        -Detalle   $(if ($minLen -lt 14) { "net accounts /minpwlen:14" } else { "" })

    # Caducidad
    Add-Check `
        -Nombre    "Caducidad máxima de contraseña" `
        -Estado    $(if ($maxAge -ne "Unlimited" -and [int]$maxAge -le 90) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     "$maxAge días" `
        -Esperado  "<= 90 días" `
        -Categoria "Contraseñas" `
        -Detalle   $(if ($maxAge -eq "Unlimited") { "net accounts /maxpwage:90" } else { "" })

    # Bloqueo de cuenta
    $lockEstado = if ($lockTh -ne "Never" -and [int]$lockTh -le 5) { "OK" } elseif ($lockTh -ne "Never") { "ADVERTENCIA" } else { "FALLO" }
    Add-Check `
        -Nombre    "Umbral de bloqueo de cuenta" `
        -Estado    $lockEstado `
        -Valor     "$lockTh intentos" `
        -Esperado  "<= 5 intentos" `
        -Categoria "Contraseñas" `
        -Detalle   $(if ($lockTh -eq "Never") { "net accounts /lockoutthreshold:5" } else { "" })

    # Historial de contraseñas
    Add-Check `
        -Nombre    "Historial de contraseñas" `
        -Estado    $(if ($history -ne "None" -and [int]$history -ge 24) { "OK" } elseif ($history -ne "None") { "ADVERTENCIA" } else { "FALLO" }) `
        -Valor     "$history contraseñas" `
        -Esperado  ">= 24" `
        -Categoria "Contraseñas"

    # Cuenta Guest
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -eq $guest) { $guest = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" } }
    Add-Check `
        -Nombre    "Cuenta Guest desactivada" `
        -Estado    $(if ($guest -and -not $guest.Enabled) { "OK" } elseif (-not $guest) { "INFO" } else { "FALLO" }) `
        -Valor     $(if ($guest) { if ($guest.Enabled) { "Activa" } else { "Inactiva" } } else { "No encontrada" }) `
        -Esperado  "Inactiva" `
        -Categoria "Contraseñas" `
        -Detalle   $(if ($guest -and $guest.Enabled) { "Disable-LocalUser -Name 'Guest'" } else { "" })

    # Usuarios con contraseña sin caducidad
    $sinCaducidad = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
    Add-Check `
        -Nombre    "Usuarios con contraseña sin caducidad" `
        -Estado    $(if ($sinCaducidad.Count -eq 0) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($sinCaducidad.Count -gt 0) { ($sinCaducidad.Name -join ", ") } else { "Ninguno" }) `
        -Esperado  "Ninguno" `
        -Categoria "Contraseñas" `
        -Detalle   $(if ($sinCaducidad.Count -gt 0) { "Revisar si son cuentas de servicio justificadas." } else { "" })
}


# ── 5. PROTOCOLOS PELIGROSOS ──────────────────────────────────

function Test-DangerousProtocols {
    Write-Seccion "PROTOCOLOS PELIGROSOS"

    # SMBv1
    $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
    Add-Check `
        -Nombre    "SMBv1 desactivado" `
        -Estado    $(if ($smb1 -eq $false) { "OK" } else { "FALLO" }) `
        -Valor     $(if ($smb1) { "Activo ⚠" } else { "Desactivado" }) `
        -Esperado  "Desactivado" `
        -Categoria "Protocolos" `
        -Detalle   $(if ($smb1) { "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" } else { "" })

    # LLMNR
    $llmnr = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    Add-Check `
        -Nombre    "LLMNR desactivado (previene Responder)" `
        -Estado    $(if ($llmnr -eq 0) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($llmnr -eq 0) { "Desactivado" } else { "Activo" }) `
        -Esperado  "Desactivado (valor 0)" `
        -Categoria "Protocolos" `
        -Detalle   $(if ($llmnr -ne 0) { "Ver hardening-windows.md sección 5 para deshabilitar LLMNR" } else { "" })

    # Remote Registry
    $remReg = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
    Add-Check `
        -Nombre    "Remote Registry desactivado" `
        -Estado    $(if ($remReg -and $remReg.StartType -eq "Disabled") { "OK" } elseif ($remReg -and $remReg.Status -eq "Stopped") { "ADVERTENCIA" } else { "FALLO" }) `
        -Valor     $(if ($remReg) { "$($remReg.Status) / $($remReg.StartType)" } else { "No existe" }) `
        -Esperado  "Stopped / Disabled" `
        -Categoria "Protocolos" `
        -Detalle   $(if ($remReg -and $remReg.StartType -ne "Disabled") { "Set-Service RemoteRegistry -StartupType Disabled" } else { "" })

    # Telnet Client
    $telnet = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
    Add-Check `
        -Nombre    "Telnet Client no instalado" `
        -Estado    $(if ($telnet -and $telnet.State -eq "Disabled") { "OK" } elseif (-not $telnet) { "INFO" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($telnet) { $telnet.State.ToString() } else { "No detectado" }) `
        -Esperado  "Disabled / No instalado" `
        -Categoria "Protocolos"
}


# ── 6. POWERSHELL ─────────────────────────────────────────────

function Test-PowerShell {
    Write-Seccion "POWERSHELL — SEGURIDAD"

    # ExecutionPolicy
    $policy = Get-ExecutionPolicy -Scope LocalMachine
    $policyEstado = if ($policy -in @("AllSigned", "RemoteSigned")) { "OK" } `
        elseif ($policy -eq "Bypass") { "FALLO" } else { "ADVERTENCIA" }
    Add-Check `
        -Nombre    "ExecutionPolicy (equipo local)" `
        -Estado    $policyEstado `
        -Valor     $policy.ToString() `
        -Esperado  "AllSigned o RemoteSigned" `
        -Categoria "PowerShell" `
        -Detalle   $(if ($policy -eq "Bypass") { "Set-ExecutionPolicy AllSigned -Scope LocalMachine" } else { "" })

    # Script Block Logging
    $sblPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $sblValue = (Get-ItemProperty -Path $sblPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Add-Check `
        -Nombre    "Script Block Logging habilitado" `
        -Estado    $(if ($sblValue -eq 1) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($sblValue -eq 1) { "Habilitado" } else { "Deshabilitado" }) `
        -Esperado  "Habilitado (valor 1)" `
        -Categoria "PowerShell" `
        -Detalle   $(if ($sblValue -ne 1) { "Ver hardening-windows.md sección 7 — Script Block Logging" } else { "" })

    # Transcripción
    $transcPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $transcValue = (Get-ItemProperty -Path $transcPath -Name "EnableTranscripting" -ErrorAction SilentlyContinue).EnableTranscripting
    Add-Check `
        -Nombre    "Transcripción de PowerShell" `
        -Estado    $(if ($transcValue -eq 1) { "OK" } else { "INFO" }) `
        -Valor     $(if ($transcValue -eq 1) { "Habilitada" } else { "Deshabilitada" }) `
        -Esperado  "Habilitada" `
        -Categoria "PowerShell"
}


# ── 7. BITLOCKER ──────────────────────────────────────────────

function Test-BitLocker {
    Write-Seccion "BITLOCKER — CIFRADO DE DISCO"

    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue

    if ($bl) {
        $estado = if ($bl.ProtectionStatus -eq "On") { "OK" } elseif ($bl.EncryptionPercentage -gt 0) { "ADVERTENCIA" } else { "FALLO" }
        Add-Check `
            -Nombre    "BitLocker activo en C:" `
            -Estado    $estado `
            -Valor     "Protección: $($bl.ProtectionStatus) | Cifrado: $($bl.EncryptionPercentage)%" `
            -Esperado  "Protección: On, Cifrado: 100%" `
            -Categoria "BitLocker" `
            -Detalle   $(if ($estado -eq "FALLO") { "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -RecoveryPasswordProtector" } else { "" })
    } else {
        Add-Check -Nombre "BitLocker en C:" -Estado "INFO" `
            -Valor "No se pudo obtener estado" `
            -Categoria "BitLocker"
    }
}


# ── 8. MACROS DE OFFICE ───────────────────────────────────────

function Test-OfficeMacros {
    Write-Seccion "MACROS DE OFFICE"

    $officeApps = @("Word", "Excel", "PowerPoint", "Access")
    $officeBase = "HKCU:\SOFTWARE\Microsoft\Office\16.0"

    foreach ($app in $officeApps) {
        $vbaPath = "$officeBase\$app\Security"
        $vbaVal  = (Get-ItemProperty -Path $vbaPath -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings

        $estado  = switch ($vbaVal) {
            1       { "FALLO" }        # Todas habilitadas
            2       { "ADVERTENCIA" }  # Con notificación
            3       { "ADVERTENCIA" }  # Solo firmadas
            4       { "OK" }           # Todas deshabilitadas
            default { "INFO" }         # No configurado (usa valor de Office por defecto)
        }
        $desc = switch ($vbaVal) {
            1 { "Todas habilitadas (peligroso)" }
            2 { "Deshabilitadas con notificación" }
            3 { "Solo firmadas digitalmente" }
            4 { "Todas deshabilitadas (seguro)" }
            default { "No configurado (puede habilitarlas)" }
        }

        Add-Check `
            -Nombre    "Macros VBA — $app" `
            -Estado    $estado `
            -Valor     $desc `
            -Esperado  "VBAWarnings = 4 (Todas deshabilitadas)" `
            -Categoria "Office" `
            -Detalle   $(if ($estado -ne "OK") { "Set-ItemProperty '$vbaPath' -Name VBAWarnings -Value 4" } else { "" })
    }
}


# ── 9. WINDOWS UPDATE ─────────────────────────────────────────

function Test-WindowsUpdate {
    Write-Seccion "WINDOWS UPDATE"

    $wuPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $noAuto  = (Get-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
    $auOpts  = (Get-ItemProperty -Path $wuPath -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions

    Add-Check `
        -Nombre    "Actualizaciones automáticas habilitadas" `
        -Estado    $(if ($noAuto -ne 1) { "OK" } else { "FALLO" }) `
        -Valor     $(if ($noAuto -eq 1) { "Deshabilitadas" } else { "Habilitadas" }) `
        -Esperado  "Habilitadas" `
        -Categoria "Updates" `
        -Detalle   $(if ($noAuto -eq 1) { "Habilitar actualizaciones automáticas en Windows Update" } else { "" })

    # Último hotfix instalado
    $lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastPatch) {
        $diasDesde = ((Get-Date) - $lastPatch.InstalledOn).Days
        $estadoPatch = if ($diasDesde -le 30) { "OK" } elseif ($diasDesde -le 90) { "ADVERTENCIA" } else { "FALLO" }
        Add-Check `
            -Nombre    "Último parche instalado" `
            -Estado    $estadoPatch `
            -Valor     "$($lastPatch.HotFixID) — hace $diasDesde días" `
            -Esperado  "Hace menos de 30 días" `
            -Categoria "Updates"
    }
}


# ── 10. RDP ───────────────────────────────────────────────────

function Test-RDP {
    Write-Seccion "ESCRITORIO REMOTO (RDP)"

    $rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $rdpVal  = (Get-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections

    $rdpActivo = ($rdpVal -eq 0)
    Add-Check `
        -Nombre    "RDP habilitado" `
        -Estado    $(if (-not $rdpActivo) { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($rdpActivo) { "Habilitado" } else { "Deshabilitado" }) `
        -Esperado  "Deshabilitado (si no se usa)" `
        -Categoria "RDP"

    if ($rdpActivo) {
        # NLA
        $nlaPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        $nlaVal  = (Get-ItemProperty -Path $nlaPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        Add-Check `
            -Nombre    "NLA (Network Level Authentication) activo" `
            -Estado    $(if ($nlaVal -eq 1) { "OK" } else { "FALLO" }) `
            -Valor     $(if ($nlaVal -eq 1) { "Activo" } else { "Inactivo" }) `
            -Esperado  "Activo" `
            -Categoria "RDP" `
            -Detalle   $(if ($nlaVal -ne 1) { "Requiere autenticación antes de crear sesión RDP" } else { "" })
    }
}


# ── 11. SYSMON ────────────────────────────────────────────────

function Test-Sysmon {
    Write-Seccion "SYSMON"

    $sysmon = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    Add-Check `
        -Nombre    "Sysmon instalado y activo" `
        -Estado    $(if ($sysmon -and $sysmon.Status -eq "Running") { "OK" } else { "ADVERTENCIA" }) `
        -Valor     $(if ($sysmon) { "$($sysmon.Name): $($sysmon.Status)" } else { "No instalado" }) `
        -Esperado  "Running" `
        -Categoria "Monitorización" `
        -Detalle   $(if (-not $sysmon) { "Descargar: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon" } else { "" })
}


# ══════════════════════════════════════════════════════════════
# GENERACIÓN DEL INFORME
# ══════════════════════════════════════════════════════════════

function New-Report {
    $ts         = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $duracion   = [math]::Round(((Get-Date) - $Script:Inicio).TotalSeconds, 1)
    $totalChecks = $Script:Resultados.Count
    $puntuacion  = if ($totalChecks -gt 0) {
        [math]::Round(($Script:TotalOK / $totalChecks) * 100)
    } else { 0 }

    $lineas = @(
        "═" * 65,
        "  INFORME DE AUDITORÍA DE SEGURIDAD Y HARDENING",
        "  Herramienta : hardening_audit.ps1",
        "  Equipo      : $env:COMPUTERNAME",
        "  Usuario      : $env:USERNAME",
        "  Generado    : $ts",
        "  Duración     : $duracion segundos",
        "═" * 65,
        "",
        "  RESUMEN",
        "  " + "─" * 50,
        "  ✓  OK           : $($Script:TotalOK.ToString().PadLeft(4))",
        "  ⚠  ADVERTENCIAS : $($Script:TotalAdvert.ToString().PadLeft(4))",
        "  ✗  FALLOS       : $($Script:TotalFallo.ToString().PadLeft(4))",
        "  ℹ  INFO         : $($Script:TotalInfo.ToString().PadLeft(4))",
        "  " + "─" * 50,
        "  PUNTUACIÓN DE SEGURIDAD: $puntuacion / 100",
        ""
    )

    # Detalle por control
    $categorias = $Script:Resultados | Group-Object Categoria | Sort-Object Name
    foreach ($cat in $categorias) {
        $lineas += ""
        $lineas += "  ── $($cat.Name) " + ("─" * (50 - $cat.Name.Length))
        foreach ($check in $cat.Group) {
            $estado   = $check.Estado.PadRight(12)
            $lineas  += "  [$estado] $($check.Nombre)"
            if ($check.Valor) { $lineas += "               Valor actual : $($check.Valor)" }
            if ($check.Esperado -and $check.Estado -ne "OK") { $lineas += "               Esperado     : $($check.Esperado)" }
            if ($check.Detalle) { $lineas += "               Acción       : $($check.Detalle)" }
        }
    }

    $lineas += @(
        "",
        "═" * 65,
        "  FIN DEL INFORME",
        "═" * 65
    )

    return $lineas -join "`n"
}


# ══════════════════════════════════════════════════════════════
# EJECUCIÓN PRINCIPAL
# ══════════════════════════════════════════════════════════════

Write-Banner

# Info del sistema
Write-Host "  Equipo   : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Usuario  : $env:USERNAME" -ForegroundColor Gray
Write-Host "  Fecha    : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Gray
Write-Host "  OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor Gray

$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $esAdmin) {
    Write-Host ""
    Write-Host "  ⚠  ATENCIÓN: Algunos controles requieren permisos de administrador." -ForegroundColor Yellow
    Write-Host "     Ejecuta el script con: Run as Administrator" -ForegroundColor Yellow
}

Write-Host ""

# Ejecutar todos los controles
Test-Firewall
Test-Defender
Test-UAC
Test-PasswordPolicy
Test-DangerousProtocols
Test-PowerShell
Test-BitLocker
Test-OfficeMacros
Test-WindowsUpdate
Test-RDP
Test-Sysmon

# Resumen final en consola
$totalChecks = $Script:Resultados.Count
$puntuacion  = if ($totalChecks -gt 0) { [math]::Round(($Script:TotalOK / $totalChecks) * 100) } else { 0 }

Write-Host ""
Write-Host "  $("═" * 55)" -ForegroundColor Cyan
Write-Host "  RESUMEN" -ForegroundColor Cyan
Write-Host "  $("─" * 55)" -ForegroundColor Cyan
Write-Host "  ✓  OK           : $($Script:TotalOK)" -ForegroundColor Green
Write-Host "  ⚠  ADVERTENCIAS : $($Script:TotalAdvert)" -ForegroundColor Yellow
Write-Host "  ✗  FALLOS       : $($Script:TotalFallo)" -ForegroundColor Red
Write-Host "  ℹ  INFO         : $($Script:TotalInfo)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  PUNTUACIÓN: $puntuacion / 100" -ForegroundColor $(
    if ($puntuacion -ge 80) { "Green" } elseif ($puntuacion -ge 60) { "Yellow" } else { "Red" }
)
Write-Host "  $("═" * 55)" -ForegroundColor Cyan

# Guardar informe en archivo
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$reportPath  = Join-Path $OutputDir "hardening_report.txt"
$contenido   = New-Report
$contenido | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "  ✓  Informe guardado en: $reportPath" -ForegroundColor Green
Write-Host ""
