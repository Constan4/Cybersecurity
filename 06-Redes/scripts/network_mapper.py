#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       network_mapper.py  —  Mapa Visual de Red              ║
║              Constan4 / Cybersecurity Repository             ║
╚══════════════════════════════════════════════════════════════╝

Descripción:
    Parsea el output XML de Nmap y genera:
    1. Mapa visual en consola con hosts, puertos y servicios
    2. Informe HTML completo con tarjetas por host (opcional)

    Compatible con cualquier escaneo Nmap guardado con -oX.

Requisitos:
    - Python 3.8+
    - Sin dependencias externas (solo librería estándar)
    - Archivo XML generado por Nmap con -oX

Uso:
    # Generar el XML con Nmap primero:
    nmap -sV -sC -O -Pn -oX scan.xml 192.168.1.0/24

    # Ver mapa en consola:
    python3 network_mapper.py -i scan.xml

    # Generar informe HTML:
    python3 network_mapper.py -i scan.xml --html mapa_red.html

    # Solo hosts con puertos abiertos:
    python3 network_mapper.py -i scan.xml --solo-activos

Autor:  Constan4
Repo:   https://github.com/Constan4/Cybersecurity
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
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
# CLASIFICACIÓN DE PUERTOS
# ══════════════════════════════════════════════════════════════

# Color por categoría de servicio
CATEGORIAS_PUERTO: Dict[str, tuple] = {
    # (color_consola, clase_css)
    "web":       (C.CYAN,     "web"),
    "auth":      (C.VERDE,    "auth"),
    "database":  (C.AMARILLO, "db"),
    "file":      (C.AZUL,     "file"),
    "dangerous": (C.ROJO,     "danger"),
    "other":     (C.GRIS,     "other"),
}

PUERTOS_CATEGORIA: Dict[int, str] = {
    # Web
    80: "web", 443: "web", 8080: "web", 8443: "web",
    8000: "web", 8888: "web", 3000: "web", 5000: "web",
    # Auth / Remote
    22: "auth", 23: "auth", 3389: "auth", 5900: "auth",
    5985: "auth", 5986: "auth",
    # Database
    1433: "database", 3306: "database", 5432: "database",
    27017: "database", 6379: "database", 9200: "database",
    1521: "database", 5984: "database",
    # File sharing
    21: "file", 20: "file", 445: "dangerous", 139: "dangerous",
    2049: "file", 69: "file",
    # Dangerous (vector de ataque habitual)
    135: "dangerous", 137: "dangerous", 138: "dangerous",
}

SERVICIOS_CONOCIDOS: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


# ══════════════════════════════════════════════════════════════
# MODELOS DE DATOS
# ══════════════════════════════════════════════════════════════

class Puerto:
    def __init__(self, numero: int, protocolo: str, estado: str,
                 servicio: str, version: str, banner: str):
        self.numero    = numero
        self.protocolo = protocolo
        self.estado    = estado
        self.servicio  = servicio or SERVICIOS_CONOCIDOS.get(numero, "")
        self.version   = version
        self.banner    = banner
        self.categoria = PUERTOS_CATEGORIA.get(numero, "other")

    @property
    def color(self) -> str:
        return CATEGORIAS_PUERTO[self.categoria][0]

    @property
    def css_clase(self) -> str:
        return CATEGORIAS_PUERTO[self.categoria][1]

    def __str__(self) -> str:
        svc = self.servicio or "?"
        ver = f" {self.version[:30]}" if self.version else ""
        return f"{self.numero}/{self.protocolo} {svc}{ver}"


class Host:
    def __init__(self, ip: str, hostname: str, estado: str,
                 sistema_operativo: str, puertos: List[Puerto]):
        self.ip          = ip
        self.hostname    = hostname
        self.estado      = estado
        self.os          = sistema_operativo
        self.puertos     = puertos

    @property
    def puertos_abiertos(self) -> List[Puerto]:
        return [p for p in self.puertos if p.estado == "open"]

    @property
    def color_os(self) -> str:
        os_lower = self.os.lower()
        if "windows" in os_lower:
            return C.AZUL
        if "linux" in os_lower:
            return C.VERDE
        if "mac" in os_lower or "apple" in os_lower:
            return C.MAGENTA
        return C.GRIS


# ══════════════════════════════════════════════════════════════
# PARSER XML DE NMAP
# ══════════════════════════════════════════════════════════════

def parsear_nmap_xml(ruta_xml: str) -> tuple:
    """
    Parsea un archivo XML de Nmap y extrae la información de hosts y puertos.

    Args:
        ruta_xml: Ruta al archivo .xml generado por nmap -oX

    Returns:
        Tupla (lista_de_hosts, metadatos_del_escaneo).

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ET.ParseError: Si el XML no es válido.
    """
    if not os.path.exists(ruta_xml):
        raise FileNotFoundError(f"Archivo no encontrado: {ruta_xml}")

    tree = ET.parse(ruta_xml)
    root = tree.getroot()

    # Metadatos del escaneo
    meta = {
        "comando":    root.get("args", "nmap"),
        "version":    root.get("version", ""),
        "inicio":     root.get("startstr", ""),
        "duracion":   "?",
    }

    runstats = root.find("runstats/finished")
    if runstats is not None:
        elapsed = runstats.get("elapsed", "")
        meta["duracion"] = f"{float(elapsed):.1f}s" if elapsed else "?"

    hosts: List[Host] = []

    for host_el in root.findall("host"):
        # Estado del host
        status_el = host_el.find("status")
        estado    = status_el.get("state", "unknown") if status_el is not None else "unknown"

        # Dirección IP
        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr", "")
                break

        if not ip:
            continue

        # Hostname
        hostname  = ""
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # Sistema operativo
        sistema_os = ""
        osmatch_el = host_el.find("os/osmatch")
        if osmatch_el is not None:
            sistema_os = osmatch_el.get("name", "")

        # Puertos
        puertos: List[Puerto] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                numero    = int(port_el.get("portid", 0))
                protocolo = port_el.get("protocol", "tcp")

                state_el  = port_el.find("state")
                p_estado  = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                if service_el is not None:
                    servicio = service_el.get("name", "")
                    version  = " ".join(filter(None, [
                        service_el.get("product", ""),
                        service_el.get("version", ""),
                    ]))
                    banner = service_el.get("extrainfo", "")
                else:
                    servicio = version = banner = ""

                puertos.append(Puerto(numero, protocolo, p_estado,
                                      servicio, version, banner))

        hosts.append(Host(ip, hostname, estado, sistema_os, puertos))

    # Ordenar por IP
    hosts.sort(key=lambda h: [int(x) for x in h.ip.split(".")])
    return hosts, meta


# ══════════════════════════════════════════════════════════════
# MAPA VISUAL EN CONSOLA
# ══════════════════════════════════════════════════════════════

def imprimir_mapa(hosts: List[Host], meta: Dict, solo_activos: bool) -> None:
    """Imprime el mapa de red en consola con formato visual."""

    hosts_filtrados = [h for h in hosts if not solo_activos or h.puertos_abiertos]
    activos         = [h for h in hosts if h.puertos_abiertos]
    inactivos       = [h for h in hosts if not h.puertos_abiertos]

    # Banner
    print(f"\n{C.CYAN}{C.NEGRITA}{'═'*65}{C.RESET}")
    print(f"{C.CYAN}{C.NEGRITA}  MAPA DE RED — network_mapper.py{C.RESET}")
    print(f"{C.CYAN}{'═'*65}{C.RESET}\n")

    # Metadatos del escaneo
    print(f"  {C.GRIS}Comando  : {meta['comando'][:80]}{C.RESET}")
    print(f"  {C.GRIS}Escaneo  : {meta['inicio']}  (duración: {meta['duracion']}){C.RESET}")
    print(f"  {C.GRIS}Hosts    : {len(hosts)} descubiertos, "
          f"{len(activos)} con puertos abiertos{C.RESET}")
    print()

    # Leyenda de colores
    print(f"  {C.NEGRITA}Leyenda:{C.RESET}  ", end="")
    for cat, (color, _) in CATEGORIAS_PUERTO.items():
        print(f"{color}■ {cat}{C.RESET}  ", end="")
    print("\n")

    # Mapa por host
    for host in hosts_filtrados:
        puertos_ab = host.puertos_abiertos

        # Cabecera del host
        os_str   = f"  {host.color_os}[{host.os[:40]}]{C.RESET}" if host.os else ""
        host_str = f"{host.hostname}" if host.hostname else ""

        print(f"  {C.NEGRITA}{'─'*63}{C.RESET}")
        print(f"  {C.NEGRITA}┌─ {host.ip}{C.RESET}"
              f"  {C.GRIS}{host_str}{C.RESET}{os_str}")

        if not puertos_ab:
            estado_color = C.VERDE if host.estado == "up" else C.ROJO
            print(f"  │  {estado_color}Sin puertos abiertos detectados{C.RESET}")
        else:
            # Cabecera de la tabla
            print(f"  │  {C.NEGRITA}{'Puerto':<14} {'Estado':<10} "
                  f"{'Servicio':<16} {'Versión'}{C.RESET}")
            print(f"  │  {'─'*58}")

            for puerto in sorted(puertos_ab, key=lambda p: p.numero):
                color   = puerto.color
                version = puerto.version[:28] if puerto.version else ""
                print(f"  │  {color}{str(puerto.numero) + '/' + puerto.protocolo:<14}"
                      f"{'open':<10}"
                      f"{(puerto.servicio or '?'):<16}{C.RESET}"
                      f"{C.GRIS}{version}{C.RESET}")

        print(f"  └{'─'*62}")

    # Resumen de hosts inactivos
    if inactivos and not solo_activos:
        print(f"\n  {C.GRIS}Hosts sin puertos abiertos detectados: "
              f"{', '.join(h.ip for h in inactivos)}{C.RESET}")

    # Estadísticas finales
    total_puertos = sum(len(h.puertos_abiertos) for h in activos)
    print(f"\n{C.CYAN}{'═'*65}{C.RESET}")
    print(f"  {C.VERDE}✓{C.RESET} {len(activos)} host(s) con puertos abiertos | "
          f"{total_puertos} puerto(s) abiertos en total")
    print(f"{C.CYAN}{'═'*65}{C.RESET}\n")


# ══════════════════════════════════════════════════════════════
# GENERADOR DE INFORME HTML
# ══════════════════════════════════════════════════════════════

COLORES_CSS = {
    "web":     "#06b6d4",
    "auth":    "#22c55e",
    "db":      "#f59e0b",
    "file":    "#3b82f6",
    "danger":  "#ef4444",
    "other":   "#6b7280",
}

def generar_html(hosts: List[Host], meta: Dict, ruta_salida: str) -> None:
    """
    Genera un informe HTML completo con tarjetas por host.

    Args:
        hosts:       Lista de hosts del escaneo.
        meta:        Metadatos del escaneo Nmap.
        ruta_salida: Ruta donde guardar el .html.
    """
    activos = [h for h in hosts if h.puertos_abiertos]
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Construir las tarjetas de host
    def badge(puerto: Puerto) -> str:
        color = COLORES_CSS.get(puerto.css_clase, "#6b7280")
        ver   = f" · {puerto.version[:25]}" if puerto.version else ""
        svc   = puerto.servicio or "?"
        return (f'<span class="badge" style="background:{color}" '
                f'title="{svc}{ver}">'
                f'{puerto.numero}/{puerto.protocolo} {svc}</span>')

    def tarjeta_host(host: Host) -> str:
        hn      = f'<span class="hostname">{host.hostname}</span>' if host.hostname else ""
        os_str  = f'<div class="os-label">{host.os}</div>' if host.os else ""
        badges  = "".join(badge(p) for p in sorted(host.puertos_abiertos, key=lambda p: p.numero))
        n_ports = len(host.puertos_abiertos)
        color_card = "#1a2942" if host.puertos_abiertos else "#1a1a2e"

        return f"""
        <div class="host-card" style="border-left: 4px solid {'#22c55e' if host.puertos_abiertos else '#374151'}">
          <div class="host-header">
            <span class="host-ip">{host.ip}</span>
            {hn}
            <span class="port-count">{n_ports} puerto{'s' if n_ports != 1 else ''}</span>
          </div>
          {os_str}
          <div class="badges">{badges if badges else '<span class="no-ports">Sin puertos abiertos</span>'}</div>
        </div>"""

    tarjetas = "\n".join(tarjeta_host(h) for h in hosts)

    # Estadísticas
    total_puertos = sum(len(h.puertos_abiertos) for h in activos)
    dist_servicios: Dict[str, int] = {}
    for host in activos:
        for p in host.puertos_abiertos:
            svc = p.servicio or str(p.numero)
            dist_servicios[svc] = dist_servicios.get(svc, 0) + 1
    top_svc = sorted(dist_servicios.items(), key=lambda x: x[1], reverse=True)[:8]
    stats_html = "".join(
        f'<div class="stat-item"><span>{svc}</span><span class="stat-count">{n}</span></div>'
        for svc, n in top_svc
    )

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mapa de Red — {meta.get('inicio', ts)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
  h1 {{ color: #38bdf8; font-size: 1.8rem; margin-bottom: 0.5rem; }}
  .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; font-family: monospace; }}
  .stats-bar {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat-box {{ background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; min-width: 140px; }}
  .stat-box .number {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
  .stat-box .label {{ color: #64748b; font-size: 0.85rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 1rem; }}
  .host-card {{ background: #1e293b; border-radius: 8px; padding: 1.2rem; transition: transform .15s; }}
  .host-card:hover {{ transform: translateY(-2px); }}
  .host-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; flex-wrap: wrap; }}
  .host-ip {{ font-size: 1.1rem; font-weight: bold; color: #e2e8f0; font-family: monospace; }}
  .hostname {{ color: #64748b; font-size: 0.85rem; font-family: monospace; }}
  .port-count {{ margin-left: auto; background: #0f172a; color: #38bdf8; border-radius: 999px; padding: 2px 10px; font-size: 0.8rem; }}
  .os-label {{ font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.6rem; padding: 2px 8px; background: #0f172a; border-radius: 4px; display: inline-block; }}
  .badges {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem; }}
  .badge {{ padding: 3px 10px; border-radius: 999px; font-size: 0.78rem; font-family: monospace; color: #fff; white-space: nowrap; cursor: default; }}
  .no-ports {{ color: #374151; font-size: 0.85rem; font-style: italic; }}
  .section-title {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em; margin: 2rem 0 1rem; }}
  .services-dist {{ background: #1e293b; border-radius: 8px; padding: 1rem; max-width: 400px; }}
  .stat-item {{ display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px solid #0f172a; font-size: 0.9rem; }}
  .stat-count {{ color: #38bdf8; font-weight: bold; }}
  .cmd {{ background: #0f172a; border-radius: 6px; padding: 0.8rem 1rem; font-family: monospace; font-size: 0.8rem; color: #94a3b8; margin-bottom: 2rem; overflow-x: auto; }}
  footer {{ margin-top: 3rem; color: #374151; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>

<h1>🗺️ Mapa de Red</h1>
<div class="subtitle">Generado: {ts} · network_mapper.py · Constan4/Cybersecurity</div>

<div class="cmd">$ {meta.get('comando', 'nmap ...')[:120]}</div>

<div class="stats-bar">
  <div class="stat-box">
    <div class="number">{len(hosts)}</div>
    <div class="label">Hosts totales</div>
  </div>
  <div class="stat-box">
    <div class="number">{len(activos)}</div>
    <div class="label">Con puertos abiertos</div>
  </div>
  <div class="stat-box">
    <div class="number">{total_puertos}</div>
    <div class="label">Puertos abiertos</div>
  </div>
  <div class="stat-box">
    <div class="number">{meta.get('duracion', '?')}</div>
    <div class="label">Duración escaneo</div>
  </div>
</div>

<p class="section-title">Servicios más frecuentes</p>
<div class="services-dist">{stats_html}</div>

<p class="section-title">Hosts descubiertos ({len(hosts)})</p>
<div class="grid">
{tarjetas}
</div>

<footer>network_mapper.py · Constan4/Cybersecurity · Solo para uso en entornos autorizados</footer>
</body>
</html>"""

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(html)


# ══════════════════════════════════════════════════════════════
# CLI Y PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

def parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="network_mapper.py",
        description=(
            "Parsea el output XML de Nmap y genera un mapa visual de red.\n"
            "Genera vista en consola y opcionalmente un informe HTML."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
workflow completo:
  nmap -sV -sC -O -Pn -oX scan.xml 192.168.1.0/24
  python3 network_mapper.py -i scan.xml
  python3 network_mapper.py -i scan.xml --html mapa_red.html
  python3 network_mapper.py -i scan.xml --solo-activos --html activos.html
        """
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="ARCHIVO.xml",
        help="Archivo XML generado por Nmap (nmap ... -oX ARCHIVO.xml)"
    )
    parser.add_argument(
        "--html",
        metavar="ARCHIVO.html",
        default=None,
        help="Generar informe HTML en la ruta indicada"
    )
    parser.add_argument(
        "--solo-activos",
        action="store_true",
        help="Mostrar solo hosts con al menos un puerto abierto"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desactivar colores ANSI en la salida de consola"
    )

    return parser.parse_args()


def main() -> None:
    args = parsear_argumentos()

    if args.no_color:
        C.off()

    # Parsear el XML
    try:
        print(f"\n  {C.CYAN}[*] Parseando {args.input}...{C.RESET}")
        hosts, meta = parsear_nmap_xml(args.input)
    except FileNotFoundError as e:
        print(f"  {C.ROJO}[✗] {e}{C.RESET}\n")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"  {C.ROJO}[✗] Error al parsear el XML: {e}{C.RESET}\n")
        sys.exit(1)

    if not hosts:
        print(f"  {C.AMARILLO}[!] No se encontraron hosts en el XML.{C.RESET}\n")
        sys.exit(0)

    # Mapa en consola
    imprimir_mapa(hosts, meta, solo_activos=args.solo_activos)

    # Informe HTML (opcional)
    if args.html:
        print(f"  {C.CYAN}[*] Generando informe HTML...{C.RESET}")
        generar_html(hosts, meta, args.html)
        print(f"  {C.VERDE}[✓] HTML guardado en: {args.html}{C.RESET}\n")


if __name__ == "__main__":
    main()
