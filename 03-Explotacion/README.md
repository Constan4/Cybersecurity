# 03 — Explotación

> **Fase 3 del ciclo de auditoría:** aprovechamiento de las vulnerabilidades identificadas para obtener acceso al sistema objetivo.

---

## ¿Qué es la explotación?

Una vez identificadas las vulnerabilidades (Fase 2), la explotación es el proceso de utilizar un **exploit** (código que aprovecha el fallo) junto con un **payload** (código que se ejecuta tras la explotación) para obtener acceso al sistema.

```
Vulnerabilidad  +  Exploit  +  Payload  =  Acceso al sistema
   (el fallo)     (la llave)  (lo que hace)   (sesión activa)
```

---

## Vectores de explotación

| Vector | Descripción | Ejemplo |
|--------|-------------|---------|
| **Red (remoto)** | Exploit contra servicio expuesto en red | EternalBlue vía SMB |
| **Cliente** | El objetivo ejecuta un archivo o abre un enlace | Documento Word con macro |
| **Web** | Explotación de aplicación web | SQLi, RCE vía upload |
| **Físico** | Acceso físico al dispositivo | USB con payload, BIOS |
| **Ingeniería social** | Engaño al usuario para ejecutar código | Phishing, Spear Phishing |

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [metasploit-guia.md](apuntes/metasploit-guia.md) | Guía completa de Metasploit: módulos, msfconsole, Meterpreter y cheat sheet |
| [tipos-de-payloads.md](apuntes/tipos-de-payloads.md) | Staged vs stageless, reverse vs bind, msfvenom y tabla comparativa |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [exploit_launcher.py](scripts/exploit_launcher.py) | Generador de payloads + handler .rc para Metasploit | `python3 exploit_launcher.py` |

---

## Flujo de trabajo típico

```bash
# 1. Identificar el servicio y buscar exploits disponibles
searchsploit "apache 2.4.49"
msfconsole -q -x "search type:exploit platform:windows smb"

# 2. Generar payload con exploit_launcher.py
python3 scripts/exploit_launcher.py

# 3. Lanzar el handler y esperar la conexión
msfconsole -r handler.rc

# 4. Una vez obtenida la sesión Meterpreter
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getsystem
```

---

## ⚠️ Aviso Legal

> La explotación de sistemas sin autorización expresa es un **delito grave** en la mayoría de jurisdicciones.
> Todo lo documentado aquí es para uso exclusivo en:
> - Entornos de laboratorio propios y controlados
> - Programas de Bug Bounty con scope definido
> - Auditorías con contrato y autorización firmada
