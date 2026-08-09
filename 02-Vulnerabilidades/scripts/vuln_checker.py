#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         vuln_checker.py  —  Buscador de CVEs               ║
║              Constan4 / Cybersecurity Repository             ║
╚══════════════════════════════════════════════════════════════╝

Descripción:
    Herramienta que consulta la API pública del NVD (National
    Vulnerability Database) del NIST para buscar CVEs de un
    software o versión específica.

    Muestra:
    - CVE ID y puntuación CVSS con código de color
    - Nivel de severidad (CRITICAL, HIGH, MEDIUM, LOW)
    - Descripción de la vulnerabilidad
    - CWE asociado (tipo de debilidad)
    - Fecha de publicación
    - URLs de referencia (parches, exploits, writeups)
    - Informe opcional en .txt

Requisitos:
    - Python 3.8 o superior
    - Sin dependencias externas (solo librería estándar)
    - Conexión a internet

Uso:
    python3 vuln_checker.py -k "apache httpd"
    python3 vuln_checker.py -k "apache httpd" -v "2.4.49"
    python3 vuln_checker.py -k "openssh" -s CRITICAL -n 5
    python3 vuln_checker.py -k "windows smb" -s HIGH --report
    python3 vuln_checker.py -k "log4j" -n 10 --no-color

    Con API key (mayor límite de peticiones):
    python3 vuln_checker.py -k "nginx" --api-key TU_API_KEY_NVD

Nota sobre la API del NVD:
    Sin API key: 5 peticiones / 30 segundos
    Con API key:  50 peticiones / 30 segundos
    API key gratuita: https://nvd.nist.gov/developers/request-an-api-key

Autor:  Constan4
Repo:   https://github.com/Constan4/Cybersecurity
"""

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VERSION      = "1.0"
MAX_RESULTADOS_POR_PAGINA = 2000

# Orden de preferencia para las métricas CVSS (la más reciente primero)
METRICAS_CVSS_PREFERENCIA = [
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV40",
    "cvssMetricV2",
]


# ══════════════════════════════════════════════════════════════
# COLORES Y UTILIDADES DE SALIDA
# ══════════════════════════════════════════════════════════════

class C:
    """Códigos de color ANSI."""
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
        C.ROJO = C.VERDE = C.AMARILLO = C.AZUL = ''
        C.MAGENTA = C.CYAN = C.GRIS = C.NEGRITA = C.RESET = ''


COLOR_SEVERIDAD: Dict[str, str] = {
    'CRITICAL': C.ROJO,
    'HIGH':     C.AMARILLO,
    'MEDIUM':   C.AZUL,
    'LOW':      C.VERDE,
    'NONE':     C.GRIS,
    'UNKNOWN':  C.GRIS,
}

ORDEN_SEVERIDAD: Dict[str, int] = {
    'CRITICAL': 5,
    'HIGH':     4,
    'MEDIUM':   3,
    'LOW':      2,
    'NONE':     1,
    'UNKNOWN':  0,
}


def banner() -> None:
    print(f"""{C.CYAN}{C.NEGRITA}
╔══════════════════════════════════════════════════════════╗
║        vuln_checker.py  —  v{VERSION}                        ║
║   Buscador de CVEs  ·  NVD API v2.0                      ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}""")


def color_score(score: Optional[float], severidad: str) -> str:
    """Formatea la puntuación CVSS con color según severidad."""
    color = COLOR_SEVERIDAD.get(severidad.upper(), C.GRIS)
    if score is not None:
        return f"{color}{C.NEGRITA}{score:4.1f}{C.RESET}"
    return f"{C.GRIS}  N/A{C.RESET}"


def color_severidad(severidad: str) -> str:
    """Formatea la etiqueta de severidad con color."""
    color = COLOR_SEVERIDAD.get(severidad.upper(), C.GRIS)
    return f"{color}{C.NEGRITA}{severidad:<8}{C.RESET}"


def separador(char: str = '─', largo: int = 70) -> str:
    return char * largo


# ══════════════════════════════════════════════════════════════
# CLIENTE DE LA API DEL NVD
# ══════════════════════════════════════════════════════════════

def consultar_nvd(
    keyword:    str,
    max_items:  int = 20,
    severidad:  Optional[str] = None,
    api_key:    Optional[str] = None,
    reintentos: int = 3,
) -> Tuple[List[Dict], int]:
    """
    Consulta la API NVD v2.0 y devuelve los CVEs encontrados.

    La API del NVD puede ser lenta o devolver 403 por rate-limit.
    Implementamos reintentos con espera exponencial.

    Args:
        keyword:    Término de búsqueda (ej: "apache httpd 2.4.49").
        max_items:  Número máximo de CVEs a recuperar.
        severidad:  Filtro de severidad mínima (CRITICAL, HIGH, MEDIUM, LOW).
        api_key:    API key del NVD para mayor límite de peticiones.
        reintentos: Número máximo de reintentos ante error.

    Returns:
        Tupla (lista_de_vulnerabilidades, total_disponible_en_NVD).
    """
    params: Dict[str, str] = {
        "keywordSearch":   keyword,
        "resultsPerPage":  str(min(max_items, MAX_RESULTADOS_POR_PAGINA)),
        "startIndex":      "0",
    }

    # El filtro de severidad de la API solo soporta una severidad exacta,
    # no "mínima". Filtramos por mínima nosotros en el cliente.
    # Aun así, si buscamos solo CRITICAL, sí lo mandamos a la API.
    if severidad and severidad.upper() == "CRITICAL":
        params["cvssV3Severity"] = "CRITICAL"

    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

    headers = {
        "User-Agent": f"vuln_checker.py/{VERSION}",
        "Accept":     "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key

    espera = 2  # segundos de espera inicial entre reintentos

    for intento in range(1, reintentos + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns     = data.get("vulnerabilities", [])
                total_nvd = data.get("totalResults", 0)
                return vulns, total_nvd

        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  {C.AMARILLO}[!] Rate-limit de NVD. Esperando {espera}s...{C.RESET}")
                time.sleep(espera)
                espera *= 2
            elif e.code == 404:
                return [], 0
            else:
                print(f"  {C.ROJO}[✗] Error HTTP {e.code}: {e.reason}{C.RESET}")
                if intento < reintentos:
                    time.sleep(espera)
                    espera *= 2
                else:
                    return [], 0

        except urllib.error.URLError as e:
            print(f"  {C.ROJO}[✗] Error de conexión: {e.reason}{C.RESET}")
            print(f"  {C.GRIS}    ¿Tienes conexión a internet?{C.RESET}")
            return [], 0

        except json.JSONDecodeError:
            print(f"  {C.ROJO}[✗] Error al parsear la respuesta de NVD{C.RESET}")
            return [], 0

    return [], 0


# ══════════════════════════════════════════════════════════════
# PROCESADO DE DATOS CVE
# ══════════════════════════════════════════════════════════════

def extraer_cvss(metrics: Dict) -> Tuple[Optional[float], str, str]:
    """
    Extrae la puntuación CVSS, severidad y vector string de las métricas.
    Prioriza CVSS v3.1 > v3.0 > v4.0 > v2.0.

    Returns:
        Tupla (score, severidad, vector_string).
    """
    for clave in METRICAS_CVSS_PREFERENCIA:
        entradas = metrics.get(clave, [])
        if not entradas:
            continue

        # Buscar la entrada de tipo "Primary" primero
        entrada = next((e for e in entradas if e.get("type") == "Primary"), entradas[0])
        datos   = entrada.get("cvssData", {})

        score     = datos.get("baseScore")
        severidad = datos.get("baseSeverity") or entrada.get("baseSeverity", "UNKNOWN")
        vector    = datos.get("vectorString", "")

        if score is not None:
            return float(score), severidad.upper(), vector

    return None, "UNKNOWN", ""


def extraer_descripcion(descriptions: List[Dict]) -> str:
    """Extrae la descripción en inglés, truncada a 300 caracteres."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            texto = desc.get("value", "").strip()
            return texto if len(texto) <= 300 else texto[:297] + "..."
    return "Sin descripción disponible."


def procesar_vulnerabilidad(vuln: Dict) -> Dict:
    """
    Extrae y estructura la información relevante de una entrada CVE de NVD.

    Args:
        vuln: Diccionario crudo de una vulnerabilidad de la API NVD.

    Returns:
        Diccionario con los campos procesados y normalizados.
    """
    cve = vuln.get("cve", {})

    cve_id      = cve.get("id", "N/A")
    fecha_pub   = (cve.get("published", "") or "")[:10]
    fecha_mod   = (cve.get("lastModified", "") or "")[:10]
    estado      = cve.get("vulnStatus", "N/A")

    descripcion = extraer_descripcion(cve.get("descriptions", []))
    score, severidad, vector = extraer_cvss(cve.get("metrics", {}))

    # CWEs asociados (tipo de debilidad)
    cwes: List[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            valor = desc.get("value", "")
            if valor and valor != "NVD-CWE-noinfo":
                cwes.append(valor)

    # Referencias (máximo 5, priorizando exploits y parches)
    referencias = [r.get("url", "") for r in cve.get("references", []) if r.get("url")][:5]

    return {
        "id":          cve_id,
        "score":       score,
        "severidad":   severidad,
        "vector":      vector,
        "descripcion": descripcion,
        "cwes":        cwes,
        "fecha_pub":   fecha_pub,
        "fecha_mod":   fecha_mod,
        "estado":      estado,
        "referencias": referencias,
    }


def filtrar_por_severidad_minima(cves: List[Dict], severidad_min: str) -> List[Dict]:
    """
    Filtra los CVEs cuya severidad es igual o superior al umbral indicado.

    Args:
        cves:         Lista de CVEs procesados.
        severidad_min: Severidad mínima (LOW, MEDIUM, HIGH, CRITICAL).

    Returns:
        Lista filtrada.
    """
    umbral = ORDEN_SEVERIDAD.get(severidad_min.upper(), 0)
    return [
        c for c in cves
        if ORDEN_SEVERIDAD.get(c["severidad"], 0) >= umbral
    ]


# ══════════════════════════════════════════════════════════════
# PRESENTACIÓN DE RESULTADOS
# ══════════════════════════════════════════════════════════════

def mostrar_cve(cve: Dict, indice: int) -> None:
    """Imprime la información de un CVE en formato legible y coloreado."""
    print(f"\n  {C.NEGRITA}[{indice:02d}] {cve['id']}{C.RESET}")
    print(f"       {'─'*60}")

    # Puntuación y severidad
    score_str = color_score(cve["score"], cve["severidad"])
    sev_str   = color_severidad(cve["severidad"])
    print(f"       CVSS: {score_str}  │  Severidad: {sev_str}  │  Publicado: {cve['fecha_pub']}")

    if cve["vector"]:
        print(f"       Vector: {C.GRIS}{cve['vector']}{C.RESET}")

    if cve["cwes"]:
        cwes_str = ", ".join(cve["cwes"])
        print(f"       CWE:    {C.CYAN}{cwes_str}{C.RESET}")

    # Descripción
    print(f"\n       {C.NEGRITA}Descripción:{C.RESET}")
    # Partir la descripción en líneas de ~80 chars para mejor legibilidad
    palabras = cve["descripcion"].split()
    linea    = "       "
    for palabra in palabras:
        if len(linea) + len(palabra) + 1 > 80:
            print(linea)
            linea = "       " + palabra + " "
        else:
            linea += palabra + " "
    if linea.strip():
        print(linea)

    # Referencias
    if cve["referencias"]:
        print(f"\n       {C.NEGRITA}Referencias:{C.RESET}")
        for ref in cve["referencias"]:
            print(f"       {C.GRIS}→ {ref}{C.RESET}")


def mostrar_estadisticas(cves: List[Dict]) -> None:
    """Muestra un resumen estadístico de los CVEs encontrados."""
    if not cves:
        return

    conteo: Dict[str, int] = {}
    for c in cves:
        sev = c["severidad"]
        conteo[sev] = conteo.get(sev, 0) + 1

    print(f"\n  {C.NEGRITA}Distribución de severidad:{C.RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]:
        n = conteo.get(sev, 0)
        if n:
            barra = "█" * n
            color = COLOR_SEVERIDAD.get(sev, C.GRIS)
            print(f"  {color}{sev:<10}{C.RESET}  {barra} ({n})")


# ══════════════════════════════════════════════════════════════
# GENERACIÓN DE INFORME
# ══════════════════════════════════════════════════════════════

def generar_informe(
    keyword:     str,
    cves:        List[Dict],
    total_nvd:   int,
    ruta_salida: Optional[str] = None
) -> str:
    """
    Genera un informe en texto plano con todos los CVEs encontrados.

    Args:
        keyword:     Término de búsqueda usado.
        cves:        Lista de CVEs procesados.
        total_nvd:   Total de CVEs disponibles en NVD para esta búsqueda.
        ruta_salida: Ruta personalizada para el archivo.

    Returns:
        Ruta del archivo generado.
    """
    ts    = datetime.datetime.now()
    ruta  = ruta_salida or f"cves_{keyword.replace(' ', '_')}_{ts.strftime('%Y%m%d_%H%M%S')}.txt"

    sep_doble  = '═' * 70
    sep_simple = '─' * 70

    lineas = [
        sep_doble,
        "  INFORME DE BÚSQUEDA DE CVEs",
        f"  Herramienta   : vuln_checker.py v{VERSION}",
        f"  Generado      : {ts.strftime('%d/%m/%Y a las %H:%M:%S')}",
        f"  Búsqueda      : {keyword}",
        f"  Resultados    : {len(cves)} mostrados de {total_nvd} encontrados en NVD",
        sep_doble,
        "",
    ]

    for i, cve in enumerate(cves, 1):
        lineas += [
            f"[{i:02d}] {cve['id']}",
            sep_simple,
            f"  CVSS Score : {cve['score'] if cve['score'] is not None else 'N/A'}",
            f"  Severidad  : {cve['severidad']}",
            f"  Vector     : {cve['vector'] or 'N/A'}",
            f"  CWE        : {', '.join(cve['cwes']) or 'N/A'}",
            f"  Publicado  : {cve['fecha_pub']}",
            f"  Estado     : {cve['estado']}",
            "",
            "  Descripción:",
            f"  {cve['descripcion']}",
            "",
        ]
        if cve["referencias"]:
            lineas.append("  Referencias:")
            for ref in cve["referencias"]:
                lineas.append(f"  → {ref}")
        lineas += ["", ""]

    lineas += [sep_doble, "  FIN DEL INFORME", sep_doble]

    with open(ruta, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))

    return ruta


# ══════════════════════════════════════════════════════════════
# CLI Y PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

def parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vuln_checker.py",
        description=(
            "Buscador de CVEs usando la API pública del NVD (NIST).\n"
            "Busca, filtra y presenta vulnerabilidades conocidas de un software."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
ejemplos:
  python3 vuln_checker.py -k "apache httpd"
  python3 vuln_checker.py -k "apache httpd" -v "2.4.49" -s HIGH
  python3 vuln_checker.py -k "openssh" -s CRITICAL -n 5 --report
  python3 vuln_checker.py -k "windows smb" -n 15 --report
  python3 vuln_checker.py -k "nginx" --api-key TU_API_KEY
        """
    )

    parser.add_argument(
        "-k", "--keyword",
        required=True,
        metavar="TÉRMINO",
        help="Software o término a buscar (ej: 'apache httpd', 'log4j', 'openssh')"
    )
    parser.add_argument(
        "-v", "--version",
        metavar="VERSIÓN",
        default=None,
        help="Versión del software (se añade al término de búsqueda)"
    )
    parser.add_argument(
        "-s", "--severity",
        metavar="SEVERIDAD",
        default=None,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        type=str.upper,
        help="Severidad mínima: LOW, MEDIUM, HIGH, CRITICAL"
    )
    parser.add_argument(
        "-n", "--num",
        metavar="N",
        type=int,
        default=20,
        help="Número máximo de resultados a mostrar (por defecto: 20)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Genera un informe .txt con todos los resultados"
    )
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        default=None,
        help="API key del NVD para mayor límite de peticiones (gratuita en nvd.nist.gov)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desactiva los colores ANSI en la salida"
    )

    return parser.parse_args()


def main() -> None:
    args = parsear_argumentos()

    if args.no_color:
        C.off()

    banner()

    # Construir el keyword de búsqueda
    keyword = args.keyword
    if args.version:
        keyword = f"{args.keyword} {args.version}"

    # Mostrar configuración
    print(f"  {C.NEGRITA}Búsqueda  :{C.RESET} {keyword}")
    if args.severity:
        print(f"  {C.NEGRITA}Severidad :{C.RESET} >= {args.severity}")
    print(f"  {C.NEGRITA}Máx. CVEs :{C.RESET} {args.num}")
    print(f"  {C.NEGRITA}Informe   :{C.RESET} {'Sí' if args.report else 'No'}")
    print()

    # ── Consulta a la API ───────────────────────────────────────
    print(f"  {C.CYAN}[*] Consultando NVD...{C.RESET}")
    inicio = time.time()

    vulns_raw, total_nvd = consultar_nvd(
        keyword   = keyword,
        max_items = min(args.num * 2, 200),  # pedir más por si el filtro local reduce
        severidad = args.severity,
        api_key   = args.api_key,
    )

    if not vulns_raw:
        print(f"\n  {C.AMARILLO}[!] No se encontraron CVEs para '{keyword}'{C.RESET}")
        print(f"  {C.GRIS}    Sugerencia: amplía el término de búsqueda{C.RESET}")
        sys.exit(0)

    duracion = round(time.time() - inicio, 2)
    print(f"  {C.VERDE}[✓] {total_nvd} CVEs encontrados en NVD ({duracion}s){C.RESET}\n")

    # ── Procesar y filtrar ──────────────────────────────────────
    cves = [procesar_vulnerabilidad(v) for v in vulns_raw]

    if args.severity:
        cves = filtrar_por_severidad_minima(cves, args.severity)

    # Ordenar por puntuación CVSS descendente
    cves.sort(key=lambda x: x["score"] or 0.0, reverse=True)

    # Limitar al número pedido
    cves = cves[:args.num]

    if not cves:
        print(f"  {C.AMARILLO}[!] Ningún CVE supera la severidad mínima '{args.severity}'{C.RESET}")
        sys.exit(0)

    # ── Mostrar resultados ──────────────────────────────────────
    print(f"  {separador()}")
    print(f"  {C.NEGRITA}Mostrando {len(cves)} CVE(s) — Ordenados por CVSS descendente{C.RESET}")
    print(f"  {separador()}")

    for i, cve in enumerate(cves, 1):
        mostrar_cve(cve, i)

    # ── Estadísticas ────────────────────────────────────────────
    print(f"\n  {separador()}")
    mostrar_estadisticas(cves)

    # ── Informe ─────────────────────────────────────────────────
    if args.report:
        print()
        ruta = generar_informe(keyword, cves, total_nvd)
        print(f"  {C.VERDE}[✓] Informe guardado en: {C.NEGRITA}{ruta}{C.RESET}")

    print(f"\n  {separador()}")
    print(f"  {C.VERDE}{C.NEGRITA}[✓] Búsqueda completada{C.RESET}\n")


if __name__ == "__main__":
    main()
