# 🔐 Cybersecurity — Apuntes y Herramientas

> Repositorio de ciberseguridad ofensiva y defensiva en español.  
> Apuntes de estudio, scripts originales y herramientas para el ciclo completo de auditoría.

---

## ¿Qué es este repositorio?

Un compendio de conocimiento práctico organizado en el orden lógico del ciclo de auditoría:
desde el reconocimiento inicial hasta el hardening del sistema. Cada módulo incluye
apuntes conceptuales detallados y herramientas Python/PowerShell listas para usar.

```
  Reconocimiento  →  Vulnerabilidades  →  Explotación
        ↑                                       ↓
    Hardening     ←   Post-Explotación  ←  Acceso obtenido
```

---

## 📁 Estructura del repositorio

| Módulo | Apuntes | Scripts | Descripción |
|--------|---------|---------|-------------|
| [01 — Reconocimiento](01-Reconocimiento/) | Nmap completo | `network_recon.py` | Ping Sweep, Port Scanner, Banner Grabbing |
| [02 — Vulnerabilidades](02-Vulnerabilidades/) | CVE/CVSS, OWASP Top 10 | `vuln_checker.py` | Buscador de CVEs via NVD API |
| [03 — Explotación](03-Explotacion/) | Metasploit, payloads | `exploit_launcher.py` | Generador de payloads + handler .rc |
| [04 — Post-Explotación](04-Post-Explotacion/) | Escalada, persistencia | `post_recon.py` | Script .rc de recon interno automatizado |
| [05 — Hardening](05-Hardening/) | Guía Windows, checklist | `hardening_audit.ps1` | Auditoría de cumplimiento con puntuación |
| [06 — Redes](06-Redes/) | TCP/IP, seguridad WiFi | `wifi_scanner.py` | Escáner de redes inalámbricas |
| [07 — CTF Writeups](07-CTF-Writeups/) | Metodología CTF | `ctf_toolkit.py` | Multi-herramienta para retos CTF |

---

## 🛠️ Herramientas y scripts del repo

```bash
# Reconocimiento de red (hosts + puertos + banners)
python3 01-Reconocimiento/scripts/network_recon.py -t 192.168.1.0/24 --report

# Buscar CVEs de un software concreto
python3 02-Vulnerabilidades/scripts/vuln_checker.py -k "apache httpd" -v "2.4.49" -s HIGH

# Generar payload + handler .rc para Metasploit
python3 03-Explotacion/scripts/exploit_launcher.py

# Reconocimiento interno tras obtener sesión Meterpreter
python3 04-Post-Explotacion/scripts/post_recon.py --session 1 --os windows

# Auditar el estado de seguridad de un sistema Windows
.\05-Hardening\scripts\hardening_audit.ps1 -OutputDir C:\audit

# Escanear redes WiFi cercanas
python3 06-Redes/scripts/wifi_scanner.py --interface wlan0

# Toolkit multi-función para retos CTF
python3 07-CTF-Writeups/scripts/ctf_toolkit.py
```

---

## 📚 Apuntes incluidos

| Apunte | Contenido |
|--------|-----------|
| [Nmap — Guía Completa](01-Reconocimiento/apuntes/nmap-guia-completa.md) | Tipos de escaneo, NSE scripts, outputs, cheat sheet |
| [Cómo leer un CVE](02-Vulnerabilidades/apuntes/como-leer-un-cve.md) | CVE, CVSS v3.1 (8 métricas), CWE, bases de datos, CVEs históricos |
| [OWASP Top 10 — 2021](02-Vulnerabilidades/apuntes/owasp-top10.md) | Los 10 riesgos web con ejemplos de código y mitigaciones |
| [Metasploit — Guía Completa](03-Explotacion/apuntes/metasploit-guia.md) | msfconsole, Meterpreter, sessions, módulos, cheat sheet |
| [Tipos de Payloads](03-Explotacion/apuntes/tipos-de-payloads.md) | Staged vs stageless, reverse vs bind, msfvenom, encoders |
| [Escalada de Privilegios Windows](04-Post-Explotacion/apuntes/escalada-privilegios-windows.md) | UAC bypass, getsystem, Potato attacks, WinPEAS |
| [Persistencia y Backdoors](04-Post-Explotacion/apuntes/persistencia-y-backdoors.md) | Run Keys, Scheduled Tasks, WMI, crontab, detección |
| [Hardening Windows](05-Hardening/apuntes/hardening-windows.md) | Firewall, Defender, macros, PS logging, BitLocker, ASR |
| [Checklist de Seguridad](05-Hardening/apuntes/checklist-seguridad.md) | Baseline, ciclo auditoría Red Team, eventos Blue Team |
| [Modelo TCP/IP](06-Redes/apuntes/modelo-tcpip.md) | Capas, protocolos, puertos, handshake, ARP, DNS |
| [Seguridad WiFi](06-Redes/apuntes/seguridad-wifi.md) | WPA2/WPA3, handshake cracking, PMKID, deauth, defensa |
| [Metodología CTF](07-CTF-Writeups/apuntes/metodologia-ctf.md) | Categorías, enfoque por tipo, plataformas, plantilla |

---

## ⚙️ Requisitos

```bash
# Python 3.8+
python3 --version

# Kali Linux (recomendado para módulos ofensivos)
# Los scripts de Python usan solo la librería estándar salvo excepción

# Para módulos de explotación
msfvenom --version
msfconsole --version

# PowerShell 5+ (para hardening_audit.ps1)
$PSVersionTable.PSVersion
```

---

## 🚀 Inicio rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/Constan4/Cybersecurity.git
cd Cybersecurity

# 2. Empezar por los apuntes de reconocimiento
cat 01-Reconocimiento/apuntes/nmap-guia-completa.md

# 3. Probar el primer script en tu red local (con autorización)
python3 01-Reconocimiento/scripts/network_recon.py -t 192.168.1.0/24 --solo-ping
```

---

## 📖 Marcos de referencia

Este repositorio sigue la metodología **PTES** (Penetration Testing Execution Standard)
y mapea las técnicas con el framework **MITRE ATT&CK**. Los controles defensivos
se alinean con el **CIS Controls v8** y los benchmarks del **NIST**.

---

## ⚠️ Aviso Legal

> **Todo el contenido de este repositorio es exclusivamente para fines educativos.**
>
> Las técnicas, herramientas y scripts documentados aquí deben utilizarse únicamente en:
> - Entornos de laboratorio propios y controlados
> - Sistemas con **autorización expresa y escrita** del propietario
> - Programas de Bug Bounty dentro del scope definido
> - Auditorías con contrato firmado
>
> El acceso no autorizado a sistemas informáticos es un **delito penal** en la mayoría
> de jurisdicciones. El autor no se responsabiliza del uso indebido de este material.

---

*Constan4 — Estudiante de Ciberseguridad*  
*github.com/Constan4/Cybersecurity*
