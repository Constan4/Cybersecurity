#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         network_recon.py  —  Herramienta de Reconocimiento  ║
║              Constan4 / Cybersecurity Repository             ║
╚══════════════════════════════════════════════════════════════╝

ADVERTENCIA LEGAL:
    Esta herramienta está diseñada únicamente para auditorías de
    seguridad en entornos controlados con autorización expresa.
    El uso no autorizado en redes ajenas puede constituir un delito
    penal (Art. 197 y 264 del Código Penal español).

Descripción:
    Herramienta de reconocimiento de red que combina tres técnicas:
    1. Ping Sweep      → Descubrimiento de hosts activos en la red
    2. Port Scanning   → Identificación de puertos TCP abiertos
    3. Banner Grabbing → Captura de información de servicios
    4. Informe         → Generación automática de reporte en .txt

Requisitos:
    - Python 3.8 o superior
    - Sin dependencias externas (solo librería estándar de Python)
    - Sistema operativo: Linux, Windows, macOS

Uso:
    python3 network_recon.py -t 192.168.1.0/24
    python3 network_recon.py -t 192.168.1.41 -p 1-1024
    python3 network_recon.py -t 192.168.1.0/24 --solo-ping --report
    python3 network_recon.py -t 192.168.1.41 -p 22,80,443,3389 --report

Autor:  Constan4
Repo:   https://github.com/Constan4/Cybersecurity
"""

import socket
import subprocess
import sys
import argparse
import ipaddress
import concurrent.futures
import datetime
import platform
import time
from typing import List, Dict, Optional, Tuple


# ══════════════════════════════════════════════════════════════
# COLORES ANSI (sin dependencias externas)
# ══════════════════════════════════════════════════════════════

class Colores:
    """Códigos de escape ANSI para colorear la salida en la terminal."""
    ROJO     = '\033[91m'
    VERDE    = '\033[92m'
    AMARILLO = '\033[93m'
    AZUL     = '\033[94m'
    MAGENTA  = '\033[95m'
    CYAN     = '\033[96m'
    BLANCO   = '\033[97m'
    NEGRITA  = '\033[1m'
    RESET    = '\033[0m'

    @staticmethod
    def deshabilitar() -> None:
        """Elimina los colores para sistemas que no los soportan."""
        Colores.ROJO = Colores.VERDE = Colores.AMARILLO = ''
        Colores.AZUL = Colores.MAGENTA = Colores.CYAN = ''
        Colores.BLANCO = Colores.NEGRITA = Colores.RESET = ''


# ══════════════════════════════════════════════════════════════
# DICCIONARIO DE PUERTOS Y SERVICIOS CONOCIDOS
# ══════════════════════════════════════════════════════════════

PUERTOS_CONOCIDOS: Dict[int, str] = {
    20:    'FTP-Data',
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    25:    'SMTP',
    53:    'DNS',
    67:    'DHCP-Server',
    68:    'DHCP-Client',
    69:    'TFTP',
    80:    'HTTP',
    110:   'POP3',
    111:   'RPC',
    123:   'NTP',
    135:   'MSRPC',
    139:   'NetBIOS-SSN',
    143:   'IMAP',
    161:   'SNMP',
    389:   'LDAP',
    443:   'HTTPS',
    445:   'SMB',
    465:   'SMTPS',
    514:   'Syslog',
    587:   'SMTP-Submit',
    636:   'LDAPS',
    993:   'IMAPS',
    995:   'POP3S',
    1433:  'MSSQL',
    1521:  'Oracle-DB',
    1723:  'PPTP',
    2049:  'NFS',
    3306:  'MySQL',
    3389:  'RDP',
    5432:  'PostgreSQL',
    5900:  'VNC',
    6379:  'Redis',
    8080:  'HTTP-Alt',
    8443:  'HTTPS-Alt',
    8888:  'HTTP-Alt2',
    9200:  'Elasticsearch',
    27017: 'MongoDB',
}

# Puertos por defecto si el usuario no especifica ninguno
PUERTOS_DEFECTO = '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443'


# ══════════════════════════════════════════════════════════════
# UTILIDADES DE SALIDA
# ══════════════════════════════════════════════════════════════

def mostrar_banner() -> None:
    """Muestra el banner de inicio de la herramienta."""
    print(f"""
{Colores.CYAN}{Colores.NEGRITA}
╔══════════════════════════════════════════════════════════╗
║           network_recon.py  —  v1.0                     ║
║   Herramienta de Reconocimiento de Red                   ║
║   Ping Sweep · Port Scan · Banner Grabbing               ║
║                                                          ║
║   ⚠  Solo para uso en entornos autorizados              ║
╚══════════════════════════════════════════════════════════╝
{Colores.RESET}""")


def log_info(mensaje: str) -> None:
    print(f"{Colores.CYAN}[*]{Colores.RESET} {mensaje}")


def log_ok(mensaje: str) -> None:
    print(f"{Colores.VERDE}[+]{Colores.RESET} {mensaje}")


def log_warn(mensaje: str) -> None:
    print(f"{Colores.AMARILLO}[!]{Colores.RESET} {mensaje}")


def log_error(mensaje: str) -> None:
    print(f"{Colores.ROJO}[✗]{Colores.RESET} {mensaje}")


def log_seccion(titulo: str) -> None:
    separador = '─' * 55
    print(f"\n{Colores.MAGENTA}{separador}{Colores.RESET}")
    print(f"{Colores.MAGENTA}{Colores.NEGRITA}  {titulo}{Colores.RESET}")
    print(f"{Colores.MAGENTA}{separador}{Colores.RESET}\n")


# ══════════════════════════════════════════════════════════════
# FASE 1: DESCUBRIMIENTO DE HOSTS (PING SWEEP)
# ══════════════════════════════════════════════════════════════

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Comprueba si un host está activo enviándole un ping ICMP.

    Usa el comando ping del sistema operativo, que es más fiable
    que implementar ICMP raw sockets (que requieren root y son
    más complejos de manejar cross-platform).

    Args:
        ip:      Dirección IP a comprobar.
        timeout: Tiempo máximo de espera en segundos.

    Returns:
        True si el host responde al ping, False en caso contrario.
    """
    sistema = platform.system().lower()

    if sistema == 'windows':
        # -n 1: un solo paquete | -w: timeout en milisegundos
        cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    else:
        # -c 1: un paquete | -W: timeout en segundos
        cmd = ['ping', '-c', '1', '-W', str(int(timeout)), ip]

    try:
        resultado = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return resultado.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def parsear_red(objetivo: str) -> List[str]:
    """
    Convierte un objetivo (IP única o rango CIDR) en una lista de IPs.

    Args:
        objetivo: IP única ('192.168.1.41') o rango CIDR ('192.168.1.0/24').

    Returns:
        Lista de strings con las IPs del rango.

    Raises:
        SystemExit si el formato no es válido.
    """
    try:
        # Intenta parsear como red CIDR (excluye dirección de red y broadcast)
        red = ipaddress.ip_network(objetivo, strict=False)
        return [str(ip) for ip in red.hosts()]
    except ValueError:
        pass

    try:
        # Intenta parsear como IP única
        ipaddress.ip_address(objetivo)
        return [objetivo]
    except ValueError:
        log_error(f"Formato de objetivo inválido: '{objetivo}'")
        log_info("Ejemplos válidos: 192.168.1.41 | 192.168.1.0/24")
        sys.exit(1)


def descubrir_hosts(objetivo: str, hilos: int = 100) -> List[str]:
    """
    Realiza un Ping Sweep concurrente sobre un rango de red.

    Usa ThreadPoolExecutor para lanzar múltiples pings en paralelo,
    reduciendo drásticamente el tiempo de escaneo en redes /24.

    Args:
        objetivo: IP o rango CIDR a analizar.
        hilos:    Número máximo de hilos concurrentes.

    Returns:
        Lista ordenada de IPs activas descubiertas.
    """
    ips = parsear_red(objetivo)
    total = len(ips)
    hosts_activos: List[str] = []

    log_seccion("FASE 1 — Descubrimiento de Hosts (Ping Sweep)")
    log_info(f"Objetivo:  {objetivo}")
    log_info(f"Rango:     {total} dirección(es) IP a analizar")
    log_info(f"Hilos:     {hilos} concurrentes\n")

    inicio = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
        futuros = {executor.submit(ping_host, ip): ip for ip in ips}

        completados = 0
        for futuro in concurrent.futures.as_completed(futuros):
            ip = futuros[futuro]
            completados += 1
            porcentaje = int((completados / total) * 100)

            # Barra de progreso en línea
            print(
                f"\r  {Colores.AMARILLO}Progreso: {porcentaje:3d}%  "
                f"[{completados}/{total}]{Colores.RESET}",
                end='',
                flush=True
            )

            try:
                if futuro.result():
                    hosts_activos.append(ip)
                    print()  # Nueva línea para el mensaje del host
                    log_ok(f"Host activo detectado: {Colores.NEGRITA}{ip}{Colores.RESET}")
            except Exception:
                pass  # Ignorar errores individuales de ping

    duracion = round(time.time() - inicio, 2)
    print()  # Línea en blanco tras la barra de progreso

    log_info(f"Ping Sweep completado en {duracion}s")
    log_info(f"Resultado: {Colores.VERDE}{Colores.NEGRITA}{len(hosts_activos)}{Colores.RESET} host(s) activo(s)\n")

    return sorted(hosts_activos, key=lambda ip: [int(x) for x in ip.split('.')])


# ══════════════════════════════════════════════════════════════
# FASE 2: ESCANEO DE PUERTOS + BANNER GRABBING
# ══════════════════════════════════════════════════════════════

def escanear_puerto(ip: str, puerto: int, timeout: float = 0.75) -> Tuple[int, bool, str]:
    """
    Intenta una conexión TCP a un puerto para comprobar si está abierto.
    Si lo está, intenta capturar el banner del servicio.

    El método es un TCP Connect Scan: completa el three-way handshake,
    lo que no requiere privilegios de root pero sí deja trazas en logs.

    Args:
        ip:      IP del host objetivo.
        puerto:  Número de puerto TCP a comprobar (1-65535).
        timeout: Tiempo máximo de espera para la conexión en segundos.

    Returns:
        Tupla (puerto, está_abierto, banner_del_servicio).
    """
    banner = ''

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, puerto))

            if resultado == 0:
                # Puerto abierto → intentar capturar el banner
                try:
                    # Enviamos una solicitud HTTP básica para provocar respuesta
                    sock.send(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
                    datos = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    # Tomar solo la primera línea, máximo 80 caracteres
                    banner = datos.split('\n')[0][:80].strip()
                except Exception:
                    pass

                return (puerto, True, banner)

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return (puerto, False, '')


def parsear_puertos(especificacion: str) -> List[int]:
    """
    Convierte una especificación de puertos a una lista de enteros.

    Soporta:
    - Puerto único:      '80'
    - Lista separada:    '22,80,443'
    - Rango:             '1-1024'
    - Combinación:       '22,80,443,8000-8100'

    Args:
        especificacion: String con la especificación de puertos.

    Returns:
        Lista de enteros con los puertos a escanear.

    Raises:
        SystemExit si el formato no es válido.
    """
    puertos: List[int] = []

    try:
        for segmento in especificacion.split(','):
            segmento = segmento.strip()
            if '-' in segmento:
                inicio, fin = segmento.split('-', 1)
                rango = range(int(inicio.strip()), int(fin.strip()) + 1)
                if any(p < 1 or p > 65535 for p in rango):
                    raise ValueError("Puerto fuera de rango")
                puertos.extend(rango)
            else:
                p = int(segmento)
                if p < 1 or p > 65535:
                    raise ValueError(f"Puerto {p} fuera de rango (1-65535)")
                puertos.append(p)
    except ValueError as error:
        log_error(f"Especificación de puertos inválida: {error}")
        log_info("Ejemplos válidos: 80 | 22,80,443 | 1-1024 | 22,80,8000-8100")
        sys.exit(1)

    return sorted(set(puertos))  # Eliminar duplicados y ordenar


def escanear_puertos(ip: str, especificacion: str, hilos: int = 150) -> List[Dict]:
    """
    Escanea un conjunto de puertos TCP en un host objetivo de forma concurrente.

    Args:
        ip:              IP del host a escanear.
        especificacion:  Especificación de puertos (ver parsear_puertos).
        hilos:           Número máximo de hilos concurrentes.

    Returns:
        Lista de diccionarios con información de los puertos abiertos,
        ordenada por número de puerto ascendente.
    """
    puertos = parsear_puertos(especificacion)
    total = len(puertos)
    puertos_abiertos: List[Dict] = []

    log_seccion(f"FASE 2 — Escaneo de Puertos en {ip}")
    log_info(f"Puertos a analizar: {total}")
    log_info(f"Hilos concurrentes: {hilos}\n")

    # Cabecera de la tabla de resultados
    print(
        f"  {Colores.NEGRITA}{'Puerto':<12} {'Estado':<10} {'Servicio':<18} {'Banner'}{Colores.RESET}"
    )
    print(f"  {'─'*12} {'─'*10} {'─'*18} {'─'*30}")

    inicio = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
        futuros = {executor.submit(escanear_puerto, ip, p): p for p in puertos}

        completados = 0
        for futuro in concurrent.futures.as_completed(futuros):
            completados += 1
            porcentaje = int((completados / total) * 100)

            print(
                f"\r  {Colores.AMARILLO}Analizando: {porcentaje:3d}%  "
                f"[{completados}/{total}]{Colores.RESET}",
                end='',
                flush=True
            )

            try:
                puerto, abierto, banner = futuro.result()

                if abierto:
                    servicio = PUERTOS_CONOCIDOS.get(puerto, 'Desconocido')
                    banner_corto = (banner[:35] + '...') if len(banner) > 35 else banner

                    print()  # Nueva línea tras la barra de progreso
                    print(
                        f"  {Colores.VERDE}{str(puerto) + '/tcp':<12} "
                        f"{'ABIERTO':<10} "
                        f"{servicio:<18} "
                        f"{Colores.AMARILLO}{banner_corto}{Colores.RESET}"
                    )

                    puertos_abiertos.append({
                        'puerto':   puerto,
                        'protocolo': 'tcp',
                        'estado':   'ABIERTO',
                        'servicio': servicio,
                        'banner':   banner,
                    })
            except Exception:
                pass

    duracion = round(time.time() - inicio, 2)
    print()

    log_info(f"Escaneo completado en {duracion}s")
    log_info(f"Resultado: {Colores.VERDE}{Colores.NEGRITA}{len(puertos_abiertos)}{Colores.RESET} puerto(s) abierto(s)\n")

    return sorted(puertos_abiertos, key=lambda x: x['puerto'])


# ══════════════════════════════════════════════════════════════
# FASE 3: GENERACIÓN DE INFORME
# ══════════════════════════════════════════════════════════════

def generar_informe(
    objetivo:    str,
    hosts:       List[str],
    resultados:  Dict[str, List[Dict]],
    ruta_salida: Optional[str] = None
) -> str:
    """
    Genera un informe en texto plano con todos los resultados del reconocimiento.

    Args:
        objetivo:    IP o rango de red analizado.
        hosts:       Lista de hosts activos descubiertos.
        resultados:  Diccionario {ip: lista_de_puertos_abiertos}.
        ruta_salida: Ruta personalizada para guardar el informe.

    Returns:
        Ruta del archivo de informe generado.
    """
    timestamp = datetime.datetime.now()
    nombre_ts = timestamp.strftime('%Y%m%d_%H%M%S')
    ruta = ruta_salida or f"recon_{nombre_ts}.txt"

    lineas: List[str] = []
    sep_doble  = '═' * 65
    sep_simple = '─' * 65

    # ── Cabecera ──────────────────────────────────────────────
    lineas += [
        sep_doble,
        '  INFORME DE RECONOCIMIENTO DE RED',
        f'  Herramienta : network_recon.py v1.0',
        f'  Generado    : {timestamp.strftime("%d/%m/%Y a las %H:%M:%S")}',
        f'  Objetivo    : {objetivo}',
        sep_doble,
        '',
    ]

    # ── Resumen de hosts activos ───────────────────────────────
    lineas += [
        '► HOSTS ACTIVOS DESCUBIERTOS',
        sep_simple,
    ]

    if hosts:
        for host in hosts:
            lineas.append(f'  [ACTIVO]  {host}')
    else:
        lineas.append('  [VACÍO]   No se encontraron hosts activos en el rango.')

    lineas.append('')

    # ── Detalle de puertos por host ────────────────────────────
    if resultados:
        lineas += [
            '► DETALLE DE PUERTOS ABIERTOS POR HOST',
            sep_simple,
        ]

        for ip, puertos in resultados.items():
            lineas.append(f'\n  Host: {ip}')
            lineas.append(f'  {"Puerto":<14} {"Estado":<12} {"Servicio":<18} {"Banner"}')
            lineas.append(f'  {"──────":<14} {"──────":<12} {"────────":<18} {"──────"}')

            if puertos:
                for p in puertos:
                    banner_txt = (p['banner'][:40] + '...') if len(p['banner']) > 40 else p['banner']
                    lineas.append(
                        f'  {str(p["puerto"]) + "/" + p["protocolo"]:<14} '
                        f'{p["estado"]:<12} '
                        f'{p["servicio"]:<18} '
                        f'{banner_txt}'
                    )
            else:
                lineas.append('  Sin puertos abiertos detectados en el rango analizado.')

    # ── Pie de informe ─────────────────────────────────────────
    lineas += [
        '',
        sep_doble,
        '  FIN DEL INFORME',
        f'  AVISO: Este informe contiene información sensible de red.',
        f'  Tratar con confidencialidad y no compartir sin autorización.',
        sep_doble,
    ]

    contenido = '\n'.join(lineas)

    with open(ruta, 'w', encoding='utf-8') as archivo:
        archivo.write(contenido)

    return ruta


# ══════════════════════════════════════════════════════════════
# CLI — ARGUMENTOS Y PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

def parsear_argumentos() -> argparse.Namespace:
    """Define y parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog='network_recon.py',
        description=(
            'Herramienta de reconocimiento de red para auditorías autorizadas.\n'
            'Combina Ping Sweep, Port Scanning y Banner Grabbing.'
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
ejemplos de uso:
  python3 network_recon.py -t 192.168.1.0/24
  python3 network_recon.py -t 192.168.1.41 -p 1-1024
  python3 network_recon.py -t 192.168.1.0/24 --solo-ping --report
  python3 network_recon.py -t 192.168.1.41 -p 22,80,443,3389 --report --no-color
        """
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        metavar='OBJETIVO',
        help='IP única (192.168.1.1) o rango CIDR (192.168.1.0/24)'
    )
    parser.add_argument(
        '-p', '--ports',
        default=PUERTOS_DEFECTO,
        metavar='PUERTOS',
        help=(
            'Puertos a escanear. Formatos:\n'
            '  80          Puerto único\n'
            '  22,80,443   Varios puertos\n'
            '  1-1024      Rango de puertos\n'
            '  22,80-90    Combinación\n'
            f'(Por defecto: puertos más comunes)'
        )
    )
    parser.add_argument(
        '--solo-ping',
        action='store_true',
        help='Solo descubrimiento de hosts, sin escanear puertos'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Genera un informe .txt con todos los resultados'
    )
    parser.add_argument(
        '--hilos',
        type=int,
        default=100,
        metavar='N',
        help='Número de hilos concurrentes (por defecto: 100)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Desactiva los colores ANSI en la salida (útil para pipes o logs)'
    )

    return parser.parse_args()


def main() -> None:
    """Función principal: orquesta las fases del reconocimiento."""
    args = parsear_argumentos()

    # Deshabilitar colores si se pide o si es Windows (puede no soportarlos)
    if args.no_color or platform.system().lower() == 'windows':
        Colores.deshabilitar()

    mostrar_banner()

    # Resumen de configuración
    print(f"  {Colores.NEGRITA}Objetivo    :{Colores.RESET} {args.target}")
    print(f"  {Colores.NEGRITA}Puertos     :{Colores.RESET} {args.ports}")
    print(f"  {Colores.NEGRITA}Hilos       :{Colores.RESET} {args.hilos}")
    print(f"  {Colores.NEGRITA}Solo ping   :{Colores.RESET} {'Sí' if args.solo_ping else 'No'}")
    print(f"  {Colores.NEGRITA}Informe     :{Colores.RESET} {'Sí' if args.report else 'No'}")
    print()
    log_warn("Usa esta herramienta SOLO en redes con autorización expresa.\n")

    # ── FASE 1: Ping Sweep ──────────────────────────────────────
    hosts_activos = descubrir_hosts(args.target, hilos=args.hilos)

    if not hosts_activos:
        log_warn("No se encontraron hosts activos.")
        log_info("Sugerencia: prueba con -Pn si el firewall bloquea ICMP.")
        sys.exit(0)

    resultados: Dict[str, List[Dict]] = {}

    # ── FASE 2: Port Scanning ───────────────────────────────────
    if not args.solo_ping:
        for host in hosts_activos:
            puertos_abiertos = escanear_puertos(host, args.ports, hilos=args.hilos)
            resultados[host] = puertos_abiertos

    # ── FASE 3: Informe ─────────────────────────────────────────
    if args.report:
        log_seccion("FASE 3 — Generación de Informe")
        ruta_informe = generar_informe(args.target, hosts_activos, resultados)
        log_ok(f"Informe guardado en: {Colores.NEGRITA}{ruta_informe}{Colores.RESET}")

    # ── Resumen final ────────────────────────────────────────────
    print(f"\n{Colores.VERDE}{Colores.NEGRITA}{'═'*55}{Colores.RESET}")
    print(f"{Colores.VERDE}{Colores.NEGRITA}  ✓  Reconocimiento completado{Colores.RESET}")
    print(f"{Colores.VERDE}{Colores.NEGRITA}{'═'*55}{Colores.RESET}\n")


if __name__ == '__main__':
    main()
