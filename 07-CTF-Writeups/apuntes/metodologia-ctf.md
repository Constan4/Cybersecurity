# Metodología CTF — Guía por Categorías

> Guía práctica para afrontar retos CTF de las categorías más comunes, con el flujo de trabajo recomendado y las herramientas necesarias en cada caso.

---

## Tabla de contenidos

1. [Metodología general](#1-metodología-general)
2. [Web](#2-web)
3. [Criptografía](#3-criptografía)
4. [Forensics](#4-forensics)
5. [Steganografía](#5-steganografía)
6. [Reversing](#6-reversing)
7. [OSINT](#7-osint)
8. [Misc y Encoding](#8-misc-y-encoding)
9. [Plantilla de Writeup](#9-plantilla-de-writeup)
10. [Cheat Sheet de comandos](#10-cheat-sheet-de-comandos)

---

## 1. Metodología general

### Los primeros 5 minutos ante cualquier reto

```bash
# 1. ¿Qué tipo de archivo/dato nos dan?
file archivo               # Tipo real del archivo (ignora la extensión)
xxd archivo | head -20     # Ver los magic bytes (primeros bytes en hex)
strings archivo | head -50 # Strings legibles
exiftool archivo           # Metadatos completos

# 2. ¿Hay algo obvio?
strings archivo | grep -i "flag\|ctf\|{" 
cat archivo | grep -o 'flag{[^}]*}'

# 3. Buscar la flag directamente
find . -name "*.txt" -exec grep -l "flag" {} \;
grep -r "flag{" . 2>/dev/null
```

### Regla de oro

> **Antes de complicarse: buscar lo simple.** Muchas flags están en texto plano,
> en metadatos o con un encoding básico. Siempre probar lo más sencillo primero.

### Magic bytes (identificar archivos por su contenido)

| Magic Bytes (hex) | Tipo |
|------------------|------|
| `FF D8 FF` | JPEG |
| `89 50 4E 47` | PNG |
| `47 49 46 38` | GIF |
| `50 4B 03 04` | ZIP |
| `7F 45 4C 46` | ELF (Linux binario) |
| `4D 5A` | PE / EXE (Windows) |
| `25 50 44 46` | PDF |
| `52 61 72 21` | RAR |
| `1F 8B` | GZIP |

```bash
# Ver magic bytes de cualquier archivo
xxd archivo | head -1
# O con Python:
python3 -c "import sys; print(open(sys.argv[1],'rb').read(16).hex())" archivo
```

---

## 2. Web

### Flujo de reconocimiento web

```bash
# 1. Ver el código fuente (hay muchas flags en comentarios HTML)
curl -s https://target.ctf/ | grep -i "flag\|<!-\|TODO"

# 2. Ver cabeceras HTTP
curl -I https://target.ctf/
curl -v https://target.ctf/ 2>&1 | grep "< "

# 3. Robots.txt y sitemap
curl https://target.ctf/robots.txt
curl https://target.ctf/sitemap.xml

# 4. Descubrimiento de rutas ocultas
gobuster dir -u https://target.ctf -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u https://target.ctf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# 5. Parámetros típicos de LFI/RFI
curl "https://target.ctf/page?file=../../../etc/passwd"
curl "https://target.ctf/page?file=php://filter/convert.base64-encode/resource=index.php"
```

### SQL Injection básico en CTF

```bash
# Probar si es vulnerable
https://target.ctf/user?id=1'   # Error SQL → vulnerable
https://target.ctf/user?id=1 OR 1=1--

# Con sqlmap (automático)
sqlmap -u "https://target.ctf/user?id=1" --dbs --batch
sqlmap -u "https://target.ctf/user?id=1" -D nombre_bd -T users --dump --batch

# Buscar la flag en la BD
sqlmap -u "..." --search -C flag --batch
```

### Cookies y JWT

```bash
# Decodificar cookie base64
echo "dXNlcm5hbWU9YWRtaW4=" | base64 -d

# Analizar JWT (JSON Web Token)
# Estructura: header.payload.signature
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" | base64 -d
# Herramienta online: jwt.io

# Probar alg:none (bypass de firma JWT)
# Cambiar "alg":"HS256" por "alg":"none" y eliminar la firma
```

---

## 3. Criptografía

### Identificar el tipo de cifrado

```
Pistas visuales:
- Solo letras A-Z (sin números): probablemente cifrado clásico (César, Vigenère)
- Solo letras A-Z con frecuencia inusual: posible sustitución monoalfabética
- Caracteres con =, ==al final: Base64
- Solo 0-9 y A-F: Hexadecimal
- Solo 0 y 1: Binario
- Números grandes: RSA, cifrado asimétrico
- Texto con patrón repetitivo: XOR con clave corta
```

### Cifrado César y ROT13

```python
# César: desplazamiento fijo de letras
# ROT13: desplazamiento de 13 (caso especial de César)

# Fuerza bruta de todos los desplazamientos de César
texto = "KHOOR ZRUOG"
for i in range(26):
    descifrado = ''.join(
        chr((ord(c) - 65 - i) % 26 + 65) if c.isalpha() else c
        for c in texto.upper()
    )
    print(f"ROT{i:2d}: {descifrado}")
# ROT 3: HELLO WORLD  ← esta es la flag
```

### RSA en CTFs

```python
# RSA débil: cuando p y q son cercanos o pequeños
# Herramienta: rsactftool
# pip install rsactftool (o usar en Kali)

# Factorizar n si es pequeño
# factordb.com — base de datos de factorizaciones conocidas

# Ataque con CRT cuando se comparte n entre dos mensajes (Common Modulus)
# Ataque de pequeño exponente e=3 (Hastad's Broadcast Attack)

# En Python: descifrar RSA si tenemos p, q, e, c
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

p, q, e = ..., ..., 65537
n = p * q
phi = (p-1) * (q-1)
d = pow(e, -1, phi)   # Inverso modular (Python 3.8+)
m = pow(c, d, n)       # Descifrar
print(m.to_bytes((m.bit_length() + 7) // 8, 'big').decode())
```

### XOR

```python
# XOR es reversible: texto XOR clave = cifrado; cifrado XOR clave = texto
# En CTFs: buscar el patrón de la clave si el texto es largo

# XOR con clave de 1 byte (fuerza bruta)
datos = bytes.fromhex("1a2b3c4d5e6f")
for clave in range(256):
    resultado = bytes([b ^ clave for b in datos])
    if all(32 <= c < 127 for c in resultado):  # Solo ASCII imprimible
        print(f"Clave {clave}: {resultado.decode()}")
```

---

## 4. Forensics

### Análisis de archivos

```bash
# Herramientas esenciales
file archivo            # Identificar tipo real
strings archivo         # Extraer texto legible
xxd archivo | head -50  # Hex dump
binwalk -e archivo      # Extraer archivos embebidos

# Análisis de imágenes de disco
fdisk -l imagen.dd
mount -o loop,offset=$((512*2048)) imagen.dd /mnt/imagen

# Recuperación de archivos borrados
foremost -i imagen.dd -o ./recuperados
testdisk imagen.dd
```

### Análisis de capturas de red (PCAP)

```bash
# Abrir con Wireshark (GUI)
wireshark captura.pcap

# Con tshark (CLI)
tshark -r captura.pcap -Y "http"                    # Solo tráfico HTTP
tshark -r captura.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
tshark -r captura.pcap -Y "dns" -T fields -e dns.qry.name  # Consultas DNS

# Exportar objetos HTTP (descargar archivos transferidos)
# Wireshark → File → Export Objects → HTTP

# Buscar credenciales en texto plano
tshark -r captura.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS"
tshark -r captura.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# Flujos TCP
tshark -r captura.pcap -z follow,tcp,ascii,0    # Seguir flujo TCP 0
```

### Análisis de memoria RAM

```bash
# Volatility 3 (el más moderno)
python3 vol.py -f memoria.raw windows.info        # Info del sistema
python3 vol.py -f memoria.raw windows.pslist      # Procesos
python3 vol.py -f memoria.raw windows.cmdline     # Líneas de comandos
python3 vol.py -f memoria.raw windows.filescan    # Archivos en memoria
python3 vol.py -f memoria.raw windows.dumpfiles --physaddr ADDR
python3 vol.py -f memoria.raw windows.hashdump    # Hashes NTLM

# Buscar la flag en memoria
strings memoria.raw | grep "flag{"
```

---

## 5. Steganografía

### Flujo de trabajo

```bash
# 1. Metadatos
exiftool imagen.png
exiftool imagen.jpg | grep -i "comment\|description\|flag"

# 2. Datos ocultos con herramientas estándar
steghide info imagen.jpg          # ¿Tiene datos ocultos? (sin contraseña)
steghide extract -sf imagen.jpg   # Extraer (pedir contraseña)
steghide extract -sf imagen.jpg -p "" -f  # Probar contraseña vacía

# 3. Análisis de LSB y otros métodos
zsteg imagen.png        # Analiza múltiples técnicas en PNG
stegsolve imagen.png    # GUI para análisis visual (Java)

# 4. Archivos incrustados
binwalk -e imagen.png   # Extraer archivos ocultos
foremost -i imagen.png  # Recuperar por magic bytes

# 5. Análisis visual
# Abrir en Stegsolve o GIMP y revisar canales de color por separado
# Canal Rojo, Verde, Azul, Alpha por separado y en combinación

# 6. Audio (MP3, WAV)
audacity audio.wav      # Buscar datos en espectrograma
sox audio.wav -n spectrogram -o espectro.png  # Ver espectro
```

### Herramientas de esteganografía más usadas en CTF

| Herramienta | Tipo | Uso |
|-------------|------|-----|
| steghide | Imágenes JPEG/BMP | Datos ocultos con contraseña |
| zsteg | PNG, BMP | LSB y otros canales |
| binwalk | Cualquier archivo | Extraer archivos embebidos |
| stegsolve | Imágenes | Análisis visual de canales |
| exiftool | Cualquier archivo | Metadatos |
| audacity | Audio | Espectrogramas |
| outguess | JPEG | LSB en coeficientes DCT |

---

## 6. Reversing

### Análisis estático

```bash
# Información básica del binario
file binario
strings binario | grep -i "flag\|pass\|key"
objdump -d binario | head -100   # Desensamblado
readelf -h binario               # Cabecera ELF

# Herramientas GUI
# Ghidra: gratuito, de la NSA, excelente decompilador
# IDA Free: el estándar de la industria
# Cutter: GUI de Radare2, gratuito

# Buscar funciones interesantes
nm -D binario | grep -i "check\|verify\|compare\|flag"
```

### Análisis dinámico

```bash
# Ejecutar y trazar llamadas al sistema
strace ./binario
ltrace ./binario   # Llamadas a funciones de librería

# Depuración con GDB
gdb ./binario
(gdb) info functions      # Listar funciones
(gdb) break main          # Punto de ruptura en main
(gdb) run                 # Ejecutar
(gdb) next / step         # Paso a paso
(gdb) print $eax          # Ver registro
(gdb) x/s 0xaddress       # Ver string en dirección
```

---

## 7. OSINT

```bash
# Buscar información sobre un dominio
whois dominio.com
dig dominio.com ANY
dnsrecon -d dominio.com

# Buscar personas
# theHarvester -d dominio.com -b google,linkedin,twitter
theHarvester -d empresa.com -b all

# Buscar en Internet Archive
# https://web.archive.org/web/*/dominio.com/*

# Shodan (dispositivos expuestos a internet)
# shodan search "apache 2.4.49 country:ES"
shodan host 1.2.3.4

# Google Dorks
# site:empresa.com filetype:pdf
# site:empresa.com "internal use only"
# inurl:admin site:empresa.com
```

---

## 8. Misc y Encoding

### Encodings más comunes en CTF

```bash
# Base64
echo "ZmxhZ3t0ZXN0fQ==" | base64 -d
echo "texto" | base64

# Hex
echo "666c61677b68657821" | xxd -r -p
echo -n "texto" | xxd -p

# Binario a texto
python3 -c "
bits = '01101000 01101001'
print(''.join(chr(int(b, 2)) for b in bits.split()))"

# ROT13
echo "uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL decode
python3 -c "from urllib.parse import unquote; print(unquote('%66%6c%61%67'))"

# HTML entities
python3 -c "from html import unescape; print(unescape('&lt;flag&gt;'))"
```

### CyberChef

[CyberChef](https://gchq.github.io/CyberChef/) es la herramienta online imprescindible para CTF. Permite encadenar operaciones de encoding/decodificación de forma visual. Acepta recetas (secuencias de operaciones) guardadas.

---

## 9. Plantilla de Writeup

```markdown
# Nombre del Reto — Plataforma CTF

**Categoría:** Web / Crypto / Forensics / Pwn / Reversing / OSINT / Misc  
**Dificultad:** Fácil / Media / Difícil  
**Puntos:** XXX  
**Fecha:** DD/MM/AAAA  
**Flag:** `flag{texto_de_la_flag}`

---

## Descripción del reto

> (Copiar el enunciado original)

**Archivos adjuntos:** archivo.zip, imagen.png...

---

## Reconocimiento

¿Qué información tenemos al inicio? ¿Qué tipo de reto parece?

```bash
file archivo
strings archivo | head -20
```

---

## Proceso de resolución

### Paso 1: ...

Descripción de la primera acción y por qué.

```bash
# Comando ejecutado
resultado
```

### Paso 2: ...

...

---

## Obtención de la flag

```
flag{texto_de_la_flag_aqui}
```

---

## Lecciones aprendidas

- ¿Qué concepto nuevo se aplicó?
- ¿Qué herramienta o técnica no conocía antes?
- ¿Cómo enfocaría este tipo de reto la próxima vez?
```

---

## 10. Cheat Sheet de comandos

```
══════════════════════════════════════════════════════════════
                  CTF CHEAT SHEET
══════════════════════════════════════════════════════════════

RECONOCIMIENTO INICIAL
  file archivo           Tipo real del archivo
  strings archivo        Texto legible
  xxd archivo | head     Magic bytes en hex
  exiftool archivo       Metadatos

ENCODING RÁPIDO
  echo "..." | base64 -d           Decodificar Base64
  echo -n "..." | base64           Codificar Base64
  echo "hex..." | xxd -r -p        Hex → texto
  echo -n "txt" | xxd -p           Texto → hex
  echo "..." | tr A-Za-z N-ZA-Mn-za-m   ROT13

WEB
  curl -I URL                      Cabeceras HTTP
  curl URL/robots.txt              Robots.txt
  gobuster dir -u URL -w wordlist  Fuzzing de rutas
  sqlmap -u "URL?id=1" --dbs       SQL Injection automático

CRYPTO
  python3 ctf_toolkit.py           Herramientas propias
  factordb.com                     Factorización RSA online
  jwt.io                           Decodificar JWT online
  cyberchef.io                     Recetas de encoding

STEGANOGRAFÍA
  steghide extract -sf img.jpg     Extraer datos ocultos
  zsteg imagen.png                 LSB y canales PNG
  binwalk -e archivo               Extraer embebidos
  strings archivo | grep flag      Buscar flag directamente

FORENSICS
  wireshark captura.pcap           Análisis de red (GUI)
  tshark -r pcap -Y "http"         Filtrar tráfico HTTP
  volatility -f mem.raw pslist     Procesos en memoria
  foremost -i imagen.dd            Recuperar archivos

REVERSING
  ghidra / ida                     Decompiladores
  gdb ./binario                    Depuración
  strings binario | grep flag      Buscar flag en binario
  strace ./binario                 Llamadas al sistema

OSINT
  whois dominio.com                Info del dominio
  theHarvester -d dominio -b all   Emails y subdominios
  shodan search "apache"           Dispositivos expuestos
  web.archive.org                  Snapshots históricos

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [CTFtime.org](https://ctftime.org) — Calendario de CTFs
- [HackTricks](https://book.hacktricks.xyz) — La biblia del CTF y pentesting
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [dCode.fr](https://www.dcode.fr) — Herramientas de cifrado clásico online
