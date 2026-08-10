#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         ctf_toolkit.py  —  Multi-herramienta para CTF       ║
║              Constan4 / Cybersecurity Repository             ║
╚══════════════════════════════════════════════════════════════╝

Descripción:
    Herramienta interactiva con funciones frecuentes en retos CTF:

    Encoding / Decoding:
    ├── Base64, Base32, Base16 (Hex), URL, HTML
    ├── Binario ↔ Texto
    └── ASCII ↔ Decimal ↔ Hex

    Cifrado Clásico:
    ├── ROT13 / Cifrado César (brute force de todos los desplazamientos)
    ├── XOR (clave de 1 byte con fuerza bruta, o clave personalizada)
    ├── Vigenère (cifrar y descifrar)
    └── Análisis de frecuencia

    Hashing:
    ├── MD5, SHA1, SHA256, SHA512 de un texto
    └── Identificar tipo de hash por longitud y caracteres

    Utilidades:
    ├── Detectar tipo de encoding automáticamente
    ├── Extraer flags con regex
    └── Análisis estadístico de texto

Uso:
    python3 ctf_toolkit.py               # Menú interactivo
    python3 ctf_toolkit.py --b64d "..."  # Base64 decode directo
    python3 ctf_toolkit.py --hex "..."   # Hex decode directo
    python3 ctf_toolkit.py --caesar "..."# Brute force César
    python3 ctf_toolkit.py --auto "..."  # Detección automática

Requisitos:
    Python 3.8+ — Solo librería estándar

Autor:  Constan4
Repo:   https://github.com/Constan4/Cybersecurity
"""

import argparse
import base64
import binascii
import hashlib
import html
import re
import string
import sys
import urllib.parse
from collections import Counter
from typing import List, Optional, Tuple


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
    def off():
        for a in ['ROJO','VERDE','AMARILLO','AZUL','MAGENTA','CYAN','GRIS','NEGRITA','RESET']:
            setattr(C, a, '')


# ══════════════════════════════════════════════════════════════
# ENCODING / DECODING
# ══════════════════════════════════════════════════════════════

def b64_encode(texto: str) -> str:
    return base64.b64encode(texto.encode()).decode()

def b64_decode(texto: str) -> str:
    # Añadir padding si falta
    padding = 4 - len(texto) % 4
    if padding != 4:
        texto += '=' * padding
    try:
        return base64.b64decode(texto).decode('utf-8', errors='replace')
    except Exception as e:
        raise ValueError(f"No es Base64 válido: {e}")

def b32_encode(texto: str) -> str:
    return base64.b32encode(texto.encode()).decode()

def b32_decode(texto: str) -> str:
    padding = (8 - len(texto) % 8) % 8
    try:
        return base64.b32decode(texto + '=' * padding).decode('utf-8', errors='replace')
    except Exception as e:
        raise ValueError(f"No es Base32 válido: {e}")

def hex_encode(texto: str) -> str:
    return texto.encode().hex()

def hex_decode(texto: str) -> str:
    texto = texto.replace(' ', '').replace('0x', '').replace('\\x', '')
    try:
        return bytes.fromhex(texto).decode('utf-8', errors='replace')
    except Exception as e:
        raise ValueError(f"No es Hex válido: {e}")

def binario_a_texto(binario: str) -> str:
    """Convierte una cadena de bits ('01001000 01101001') a texto."""
    binario = binario.replace(' ', '')
    if len(binario) % 8 != 0:
        raise ValueError("La longitud del binario no es múltiplo de 8")
    return ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))

def texto_a_binario(texto: str) -> str:
    """Convierte texto a representación binaria."""
    return ' '.join(format(ord(c), '08b') for c in texto)

def url_encode(texto: str) -> str:
    return urllib.parse.quote(texto)

def url_decode(texto: str) -> str:
    return urllib.parse.unquote(texto)

def html_encode(texto: str) -> str:
    return html.escape(texto)

def html_decode(texto: str) -> str:
    return html.unescape(texto)

def ascii_a_dec(texto: str) -> str:
    return ' '.join(str(ord(c)) for c in texto)

def dec_a_ascii(numeros: str) -> str:
    return ''.join(chr(int(n)) for n in numeros.split())


# ══════════════════════════════════════════════════════════════
# CIFRADO CLÁSICO
# ══════════════════════════════════════════════════════════════

def rot13(texto: str) -> str:
    return texto.translate(
        str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )
    )

def cesar_cifrar(texto: str, desplazamiento: int) -> str:
    resultado = []
    for c in texto:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            resultado.append(chr((ord(c) - base + desplazamiento) % 26 + base))
        else:
            resultado.append(c)
    return ''.join(resultado)

def cesar_brute_force(texto: str) -> List[Tuple[int, str]]:
    """Devuelve todos los desplazamientos posibles de César."""
    return [(i, cesar_cifrar(texto, -i)) for i in range(26)]

def xor_single_byte_brute(datos: bytes) -> List[Tuple[int, str]]:
    """
    XOR fuerza bruta con clave de 1 byte.
    Devuelve solo los resultados que son ASCII imprimible.
    """
    resultados = []
    for clave in range(256):
        resultado = bytes([b ^ clave for b in datos])
        # Filtrar solo resultados completamente imprimibles
        if all(32 <= c < 127 or c in (9, 10, 13) for c in resultado):
            texto = resultado.decode('ascii', errors='replace')
            resultados.append((clave, texto))
    return resultados

def xor_clave(datos: bytes, clave: bytes) -> bytes:
    """XOR con clave de longitud arbitraria (repetida ciclicamente)."""
    return bytes([datos[i] ^ clave[i % len(clave)] for i in range(len(datos))])

def vigenere_cifrar(texto: str, clave: str) -> str:
    clave = clave.upper()
    resultado = []
    ki = 0
    for c in texto:
        if c.isalpha():
            desp = ord(clave[ki % len(clave)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            resultado.append(chr((ord(c.upper()) - ord('A') + desp) % 26 + base))
            ki += 1
        else:
            resultado.append(c)
    return ''.join(resultado)

def vigenere_descifrar(texto: str, clave: str) -> str:
    clave = clave.upper()
    resultado = []
    ki = 0
    for c in texto:
        if c.isalpha():
            desp = ord(clave[ki % len(clave)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            resultado.append(chr((ord(c.upper()) - ord('A') - desp) % 26 + base))
            ki += 1
        else:
            resultado.append(c)
    return ''.join(resultado)

def analisis_frecuencia(texto: str) -> List[Tuple[str, int, float]]:
    """
    Análisis de frecuencia de caracteres.
    Útil para ataques a cifrados de sustitución monoalfabética.
    """
    solo_letras = [c.upper() for c in texto if c.isalpha()]
    total = len(solo_letras)
    if total == 0:
        return []
    conteo = Counter(solo_letras)
    return [(c, n, n/total*100) for c, n in sorted(conteo.items(), key=lambda x: -x[1])]


# ══════════════════════════════════════════════════════════════
# HASHING
# ══════════════════════════════════════════════════════════════

def hashear(texto: str) -> dict:
    """Calcula MD5, SHA1, SHA256 y SHA512 de un texto."""
    encoded = texto.encode()
    return {
        'MD5':    hashlib.md5(encoded).hexdigest(),
        'SHA1':   hashlib.sha1(encoded).hexdigest(),
        'SHA256': hashlib.sha256(encoded).hexdigest(),
        'SHA512': hashlib.sha512(encoded).hexdigest(),
    }

def identificar_hash(hash_str: str) -> str:
    """
    Identifica el tipo de hash por su longitud y caracteres.
    Útil para saber qué algoritmo atacar con hashcat.
    """
    h = hash_str.strip().lower()
    longitud = len(h)
    es_hex = all(c in '0123456789abcdef' for c in h)
    es_b64 = bool(re.match(r'^[A-Za-z0-9+/]+=*$', hash_str.strip()))

    if longitud == 32 and es_hex:
        return "MD5 (hashcat -m 0)"
    elif longitud == 40 and es_hex:
        return "SHA1 (hashcat -m 100)"
    elif longitud == 56 and es_hex:
        return "SHA224 (hashcat -m 1300)"
    elif longitud == 64 and es_hex:
        return "SHA256 (hashcat -m 1400)"
    elif longitud == 96 and es_hex:
        return "SHA384 (hashcat -m 10800)"
    elif longitud == 128 and es_hex:
        return "SHA512 (hashcat -m 1700)"
    elif longitud == 32 and ':' in hash_str:
        return "MD5 con salt (hashcat -m 10)"
    elif h.startswith('$2b$') or h.startswith('$2a$'):
        return "bcrypt (hashcat -m 3200)"
    elif h.startswith('$6$'):
        return "SHA512crypt (hashcat -m 1800)"
    elif h.startswith('$1$'):
        return "MD5crypt (hashcat -m 500)"
    elif longitud == 13 and not es_hex:
        return "DES crypt (hashcat -m 1500)"
    elif es_b64 and longitud in (24, 28, 44, 88):
        return f"Posible Base64 de hash ({longitud} chars)"
    else:
        return f"Tipo desconocido (longitud: {longitud})"


# ══════════════════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════════════════

FLAG_REGEX = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]{1,100}\}')

def buscar_flags(texto: str) -> List[str]:
    """Busca flags con el patrón típico de CTF: prefijo{contenido}."""
    return FLAG_REGEX.findall(texto)

def detectar_encoding(texto: str) -> List[str]:
    """
    Intenta detectar automáticamente qué tipo de encoding/cifrado tiene el texto.
    Devuelve una lista de candidatos con probabilidad.
    """
    candidatos = []
    t = texto.strip()

    # Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', t) and len(t) % 4 == 0:
        candidatos.append("Base64 (prueba: base64 -d)")

    # Base32
    if re.match(r'^[A-Z2-7]+=*$', t) and len(t) % 8 == 0:
        candidatos.append("Base32 (prueba: base32 -d)")

    # Hex
    if re.match(r'^[0-9a-fA-F\s]+$', t) and len(t.replace(' ', '')) % 2 == 0:
        candidatos.append("Hexadecimal (prueba: xxd -r -p)")

    # Binario
    if re.match(r'^[01\s]+$', t) and len(t.replace(' ', '')) % 8 == 0:
        candidatos.append("Binario (grupos de 8 bits)")

    # Solo letras → posible cifrado clásico
    if re.match(r'^[A-Za-z\s]+$', t) and len(t) > 5:
        candidatos.append("Posible cifrado clásico: César, ROT13 o Vigenère")

    # Números separados por espacios/comas → posible ASCII decimal
    if re.match(r'^[\d\s,]+$', t):
        nums = re.findall(r'\d+', t)
        if all(0 <= int(n) <= 127 for n in nums):
            candidatos.append("ASCII decimal (números → caracteres)")

    # URL encoding
    if '%' in t and re.search(r'%[0-9a-fA-F]{2}', t):
        candidatos.append("URL encoding (%xx)")

    # HTML entities
    if '&' in t and ';' in t:
        candidatos.append("HTML entities (&amp; &lt; &#xx;)")

    if not candidatos:
        candidatos.append("Tipo no detectado automáticamente — prueba manual")

    return candidatos

def intentar_todos_los_decodings(texto: str) -> dict:
    """
    Intenta decodificar el texto con todos los métodos conocidos.
    Devuelve los que producen texto legible.
    """
    resultados = {}

    metodos = {
        'Base64':   lambda t: b64_decode(t),
        'Base32':   lambda t: b32_decode(t),
        'Hex':      lambda t: hex_decode(t),
        'ROT13':    lambda t: rot13(t),
        'URL':      lambda t: url_decode(t),
        'HTML':     lambda t: html_decode(t),
    }

    for nombre, func in metodos.items():
        try:
            resultado = func(texto)
            # Solo incluir si el resultado parece texto legible
            if resultado and any(c.isalpha() for c in resultado):
                resultados[nombre] = resultado
        except Exception:
            pass

    return resultados


# ══════════════════════════════════════════════════════════════
# INTERFAZ INTERACTIVA
# ══════════════════════════════════════════════════════════════

def banner() -> None:
    print(f"""{C.CYAN}{C.NEGRITA}
╔══════════════════════════════════════════════════════════╗
║        ctf_toolkit.py  —  v1.0                          ║
║   Multi-herramienta para retos CTF                       ║
║   Encoding · Cifrado clásico · Hashing · Análisis        ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}""")


MENU_PRINCIPAL = f"""
  {C.NEGRITA}ENCODING / DECODING{C.RESET}
  {C.VERDE}1{C.RESET}  Base64 encode/decode
  {C.VERDE}2{C.RESET}  Base32 encode/decode
  {C.VERDE}3{C.RESET}  Hex encode/decode
  {C.VERDE}4{C.RESET}  Binario ↔ Texto
  {C.VERDE}5{C.RESET}  URL encode/decode
  {C.VERDE}6{C.RESET}  HTML encode/decode
  {C.VERDE}7{C.RESET}  ASCII ↔ Decimal

  {C.NEGRITA}CIFRADO CLÁSICO{C.RESET}
  {C.AMARILLO}10{C.RESET} ROT13
  {C.AMARILLO}11{C.RESET} César — Brute force (todos los desplazamientos)
  {C.AMARILLO}12{C.RESET} César — Cifrar/descifrar con desplazamiento fijo
  {C.AMARILLO}13{C.RESET} XOR — Brute force clave de 1 byte (desde Hex)
  {C.AMARILLO}14{C.RESET} XOR — Con clave personalizada
  {C.AMARILLO}15{C.RESET} Vigenère — Cifrar/descifrar
  {C.AMARILLO}16{C.RESET} Análisis de frecuencia

  {C.NEGRITA}HASHING{C.RESET}
  {C.MAGENTA}20{C.RESET} Calcular hashes (MD5, SHA1, SHA256, SHA512)
  {C.MAGENTA}21{C.RESET} Identificar tipo de hash

  {C.NEGRITA}UTILIDADES{C.RESET}
  {C.CYAN}30{C.RESET} Detección automática de encoding
  {C.CYAN}31{C.RESET} Intentar todos los decodings
  {C.CYAN}32{C.RESET} Buscar flags con regex

  {C.GRIS} 0  Salir{C.RESET}
"""

def pedir_texto(prompt: str = "Introduce el texto") -> str:
    print(f"\n  {C.AMARILLO}[?]{C.RESET} {prompt}:")
    return input("  → ").strip()

def mostrar_resultado(titulo: str, resultado: str) -> None:
    print(f"\n  {C.VERDE}[✓] {titulo}:{C.RESET}")
    print(f"  {C.NEGRITA}{resultado}{C.RESET}")
    flags = buscar_flags(resultado)
    if flags:
        print(f"\n  {C.ROJO}🚩 FLAG ENCONTRADA: {' | '.join(flags)}{C.RESET}")

def menu_encode_decode(opcion: int) -> None:
    mapa = {
        1:  ("Base64",   ("encode", b64_encode),  ("decode", b64_decode)),
        2:  ("Base32",   ("encode", b32_encode),  ("decode", b32_decode)),
        3:  ("Hex",      ("encode", hex_encode),  ("decode", hex_decode)),
        5:  ("URL",      ("encode", url_encode),  ("decode", url_decode)),
        6:  ("HTML",     ("encode", html_encode), ("decode", html_decode)),
    }
    nombre, (enc_n, enc_f), (dec_n, dec_f) = mapa[opcion]

    accion = input(f"\n  {C.AMARILLO}[?]{C.RESET} {nombre} — (e)ncode o (d)ecode: ").strip().lower()
    texto  = pedir_texto()

    if accion in ('e', 'encode'):
        mostrar_resultado(f"{nombre} encode", enc_f(texto))
    elif accion in ('d', 'decode'):
        try:
            mostrar_resultado(f"{nombre} decode", dec_f(texto))
        except ValueError as e:
            print(f"\n  {C.ROJO}[✗] Error: {e}{C.RESET}")

def run_interactive() -> None:
    banner()

    while True:
        print(MENU_PRINCIPAL)
        opcion_str = input(f"  {C.AMARILLO}Opción:{C.RESET} ").strip()

        try:
            opcion = int(opcion_str)
        except ValueError:
            continue

        if opcion == 0:
            print(f"\n  {C.GRIS}Hasta luego.{C.RESET}\n")
            break

        # ── Encoding ──────────────────────────────────────────
        elif opcion in (1, 2, 3, 5, 6):
            menu_encode_decode(opcion)

        elif opcion == 4:
            accion = input(f"\n  {C.AMARILLO}[?]{C.RESET} Binario→Texto (b) o Texto→Binario (t): ").strip().lower()
            texto = pedir_texto()
            if accion == 'b':
                try:
                    mostrar_resultado("Binario → Texto", binario_a_texto(texto))
                except ValueError as e:
                    print(f"\n  {C.ROJO}[✗] {e}{C.RESET}")
            else:
                mostrar_resultado("Texto → Binario", texto_a_binario(texto))

        elif opcion == 7:
            accion = input(f"\n  {C.AMARILLO}[?]{C.RESET} ASCII→Decimal (a) o Decimal→ASCII (d): ").strip().lower()
            texto = pedir_texto()
            if accion == 'a':
                mostrar_resultado("ASCII → Decimal", ascii_a_dec(texto))
            else:
                try:
                    mostrar_resultado("Decimal → ASCII", dec_a_ascii(texto))
                except Exception as e:
                    print(f"\n  {C.ROJO}[✗] Error: {e}{C.RESET}")

        # ── Cifrado clásico ────────────────────────────────────
        elif opcion == 10:
            texto = pedir_texto()
            mostrar_resultado("ROT13", rot13(texto))

        elif opcion == 11:
            texto = pedir_texto()
            print(f"\n  {C.CYAN}[*] Todos los desplazamientos César:{C.RESET}\n")
            for desp, resultado in cesar_brute_force(texto):
                flags = buscar_flags(resultado)
                marcador = f"  {C.ROJO}← FLAG!{C.RESET}" if flags else ""
                print(f"  ROT{str(desp).zfill(2)}: {resultado}{marcador}")

        elif opcion == 12:
            texto = pedir_texto()
            desp  = int(input(f"  {C.AMARILLO}[?]{C.RESET} Desplazamiento (1-25): ").strip())
            accion = input(f"  {C.AMARILLO}[?]{C.RESET} (c)ifrar o (d)escifrar: ").strip().lower()
            if accion == 'c':
                mostrar_resultado(f"César +{desp}", cesar_cifrar(texto, desp))
            else:
                mostrar_resultado(f"César -{desp}", cesar_cifrar(texto, -desp))

        elif opcion == 13:
            hex_texto = pedir_texto("Introduce el texto en hexadecimal (ej: 1a2b3c)")
            try:
                datos = bytes.fromhex(hex_texto.replace(' ', ''))
                resultados = xor_single_byte_brute(datos)
                if resultados:
                    print(f"\n  {C.CYAN}[*] Resultados XOR con clave de 1 byte:{C.RESET}\n")
                    for clave, texto in resultados:
                        flags = buscar_flags(texto)
                        marcador = f"  {C.ROJO}← FLAG!{C.RESET}" if flags else ""
                        print(f"  0x{clave:02X} ({clave:3d}): {texto[:80]}{marcador}")
                else:
                    print(f"\n  {C.AMARILLO}[!] No se encontraron resultados ASCII imprimibles{C.RESET}")
            except ValueError as e:
                print(f"\n  {C.ROJO}[✗] Hex inválido: {e}{C.RESET}")

        elif opcion == 14:
            texto_hex = pedir_texto("Texto en hexadecimal (o texto plano)")
            clave_str = pedir_texto("Clave XOR (texto o hex con prefijo 0x)")

            try:
                datos = bytes.fromhex(texto_hex.replace(' ', '')) if all(c in '0123456789abcdefABCDEF ' for c in texto_hex) else texto_hex.encode()
                clave = bytes.fromhex(clave_str[2:]) if clave_str.startswith('0x') else clave_str.encode()
                resultado_bytes = xor_clave(datos, clave)
                resultado_hex   = resultado_bytes.hex()
                resultado_txt   = resultado_bytes.decode('utf-8', errors='replace')
                print(f"\n  {C.VERDE}[✓] XOR resultado (hex):{C.RESET}  {resultado_hex}")
                print(f"  {C.VERDE}[✓] XOR resultado (txt):{C.RESET}  {resultado_txt}")
                flags = buscar_flags(resultado_txt)
                if flags:
                    print(f"\n  {C.ROJO}🚩 FLAG: {' | '.join(flags)}{C.RESET}")
            except Exception as e:
                print(f"\n  {C.ROJO}[✗] Error: {e}{C.RESET}")

        elif opcion == 15:
            accion = input(f"\n  {C.AMARILLO}[?]{C.RESET} (c)ifrar o (d)escifrar: ").strip().lower()
            texto = pedir_texto()
            clave = pedir_texto("Clave Vigenère")
            if accion == 'c':
                mostrar_resultado("Vigenère cifrado", vigenere_cifrar(texto, clave))
            else:
                mostrar_resultado("Vigenère descifrado", vigenere_descifrar(texto, clave))

        elif opcion == 16:
            texto = pedir_texto()
            freqs = analisis_frecuencia(texto)
            print(f"\n  {C.CYAN}[*] Análisis de frecuencia (letras en inglés: E T A O I N S H R){C.RESET}\n")
            for letra, count, pct in freqs[:10]:
                barra = "█" * int(pct / 2)
                print(f"  {C.VERDE}{letra}{C.RESET}  {barra:<25} {pct:.1f}% ({count})")

        # ── Hashing ────────────────────────────────────────────
        elif opcion == 20:
            texto = pedir_texto()
            hashes = hashear(texto)
            print(f"\n  {C.CYAN}[*] Hashes de: '{texto}'{C.RESET}\n")
            for algo, valor in hashes.items():
                print(f"  {C.VERDE}{algo:<8}{C.RESET}  {valor}")

        elif opcion == 21:
            hash_str = pedir_texto("Introduce el hash a identificar")
            tipo = identificar_hash(hash_str)
            print(f"\n  {C.VERDE}[✓] Tipo probable:{C.RESET} {tipo}")

        # ── Utilidades ─────────────────────────────────────────
        elif opcion == 30:
            texto = pedir_texto()
            candidatos = detectar_encoding(texto)
            print(f"\n  {C.CYAN}[*] Encodings detectados:{C.RESET}")
            for c in candidatos:
                print(f"  {C.VERDE}  →{C.RESET} {c}")

        elif opcion == 31:
            texto = pedir_texto()
            resultados = intentar_todos_los_decodings(texto)
            if resultados:
                print(f"\n  {C.CYAN}[*] Resultados de decodings exitosos:{C.RESET}\n")
                for metodo, resultado in resultados.items():
                    print(f"  {C.VERDE}{metodo:<10}{C.RESET}  {resultado[:100]}")
                    flags = buscar_flags(resultado)
                    if flags:
                        print(f"  {C.ROJO}           🚩 FLAG: {' | '.join(flags)}{C.RESET}")
            else:
                print(f"\n  {C.AMARILLO}[!] No se pudieron decodificar automáticamente{C.RESET}")

        elif opcion == 32:
            texto = pedir_texto("Introduce el texto donde buscar flags")
            flags = buscar_flags(texto)
            if flags:
                print(f"\n  {C.ROJO}🚩 FLAGS ENCONTRADAS:{C.RESET}")
                for f in flags:
                    print(f"  {C.NEGRITA}  → {f}{C.RESET}")
            else:
                print(f"\n  {C.AMARILLO}[!] No se encontraron flags con el patrón {{prefijo}}{{contenido}}{C.RESET}")

        else:
            print(f"\n  {C.ROJO}[!] Opción no válida{C.RESET}")

        input(f"\n  {C.GRIS}[Enter para continuar]{C.RESET}")


# ══════════════════════════════════════════════════════════════
# CLI DIRECTO (sin menú)
# ══════════════════════════════════════════════════════════════

def parsear_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ctf_toolkit.py",
        description="Multi-herramienta para retos CTF — encoding, cifrado, hashing y análisis.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
ejemplos rápidos:
  python3 ctf_toolkit.py --b64d "ZmxhZ3t0ZXN0fQ=="
  python3 ctf_toolkit.py --hex "666c61677b7465737421"
  python3 ctf_toolkit.py --caesar "KHOOR ZRUOG"
  python3 ctf_toolkit.py --rot13 "syne{grfg}"
  python3 ctf_toolkit.py --hash "password123"
  python3 ctf_toolkit.py --identify "5f4dcc3b5aa765d61d8327deb882cf99"
  python3 ctf_toolkit.py --auto "ZmxhZ3t0ZXN0fQ=="
        """
    )
    parser.add_argument("--b64d",     metavar="TEXT",  help="Base64 decode")
    parser.add_argument("--b64e",     metavar="TEXT",  help="Base64 encode")
    parser.add_argument("--hex",      metavar="HEX",   help="Hex decode")
    parser.add_argument("--caesar",   metavar="TEXT",  help="César brute force (todos los desplazamientos)")
    parser.add_argument("--rot13",    metavar="TEXT",  help="ROT13")
    parser.add_argument("--hash",     metavar="TEXT",  help="Calcular hashes (MD5, SHA1, SHA256, SHA512)")
    parser.add_argument("--identify", metavar="HASH",  help="Identificar tipo de hash")
    parser.add_argument("--auto",     metavar="TEXT",  help="Detección automática de encoding + intentar decodificar")
    parser.add_argument("--no-color", action="store_true", help="Sin colores ANSI")
    return parser.parse_args()


def main() -> None:
    args = parsear_argumentos()

    if args.no_color:
        C.off()

    # Modo CLI directo (sin menú)
    if any([args.b64d, args.b64e, args.hex, args.caesar,
            args.rot13, args.hash, args.identify, args.auto]):

        if args.b64d:
            print(b64_decode(args.b64d))
        if args.b64e:
            print(b64_encode(args.b64e))
        if args.hex:
            print(hex_decode(args.hex))
        if args.rot13:
            print(rot13(args.rot13))
        if args.caesar:
            for desp, res in cesar_brute_force(args.caesar):
                print(f"ROT{desp:02d}: {res}")
        if args.hash:
            for algo, val in hashear(args.hash).items():
                print(f"{algo}: {val}")
        if args.identify:
            print(identificar_hash(args.identify))
        if args.auto:
            candidatos = detectar_encoding(args.auto)
            print("Encodings detectados:")
            for c in candidatos:
                print(f"  → {c}")
            resultados = intentar_todos_los_decodings(args.auto)
            if resultados:
                print("\nDecodings exitosos:")
                for m, r in resultados.items():
                    print(f"  {m}: {r}")
    else:
        # Modo interactivo
        run_interactive()


if __name__ == "__main__":
    main()
