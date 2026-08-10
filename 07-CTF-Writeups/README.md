# 07 — CTF Writeups

> **Capture The Flag:** competiciones de ciberseguridad donde el objetivo es encontrar una "flag" (cadena de texto como `flag{texto_secreto}`) resolviendo retos técnicos de distintas categorías.

---

## ¿Para qué sirven los CTFs?

Los CTFs son la forma más práctica de aprender ciberseguridad de forma legal y controlada. Desarrollan habilidades reales en un entorno donde equivocarse no tiene consecuencias.

```
CTF  →  Aprendizaje práctico
     →  Construcción de portfolio
     →  Certificaciones (OSCP, CEH, eJPT requieren mentalidad CTF)
     →  Comunidad y networking
```

---

## Plataformas recomendadas

| Plataforma | Tipo | Nivel | Descripción |
|------------|------|-------|-------------|
| [HackTheBox](https://hackthebox.com) | Máquinas + Challenges | Intermedio-Avanzado | Las máquinas más realistas del mercado |
| [TryHackMe](https://tryhackme.com) | Aprendizaje guiado | Principiante | Ideal para empezar, con ruta de aprendizaje |
| [PicoCTF](https://picoctf.org) | Competición | Principiante-Intermedio | Organizado por Carnegie Mellon University |
| [CTFtime](https://ctftime.org) | Calendario | Todos | Agenda de todos los CTFs del mundo |
| [PortSwigger Web](https://portswigger.net/web-security) | Web | Principiante-Avanzado | Los mejores labs de seguridad web (gratis) |
| [Root-Me](https://root-me.org) | Challenges | Todos | Gran variedad de categorías |
| [VulnHub](https://vulnhub.com) | VMs | Intermedio | Máquinas para descargar y practicar offline |

---

## Categorías de retos

| Categoría | Descripción | Herramientas clave |
|-----------|-------------|-------------------|
| **Web** | XSS, SQLi, SSRF, LFI, RCE... | Burp Suite, curl, sqlmap |
| **Pwn (Binary Exploitation)** | Buffer overflow, ROP, format strings | GDB, pwntools, ROPgadget |
| **Reversing** | Ingeniería inversa de binarios | Ghidra, IDA, Cutter, strings |
| **Crypto** | Criptografía clásica y moderna | Python, CyberChef, hashcat |
| **Forensics** | Análisis de archivos, memoria, pcap | Wireshark, Autopsy, Volatility |
| **Steganografía** | Datos ocultos en imágenes/audio | steghide, binwalk, exiftool |
| **OSINT** | Inteligencia en fuentes abiertas | Shodan, theHarvester, Maltego |
| **Misc** | Retos variados que no encajan en otras categorías | ctf_toolkit.py |

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [metodologia-ctf.md](apuntes/metodologia-ctf.md) | Enfoque por categoría, herramientas esenciales y plantilla de writeup |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [ctf_toolkit.py](scripts/ctf_toolkit.py) | Multi-herramienta: encoding, cifrado clásico, hashing, análisis | `python3 ctf_toolkit.py` |

### 📄 Writeups

*Los writeups de retos resueltos se añadirán aquí organizados por plataforma y categoría.*

```
07-CTF-Writeups/
└── writeups/
    ├── HackTheBox/
    │   └── machine-name.md
    ├── TryHackMe/
    │   └── room-name.md
    └── PicoCTF/
        └── challenge-name.md
```

---

## Flujo de trabajo rápido ante un reto

```bash
# 1. Identificar qué tipo de reto es
file archivo_misterioso    # Tipo de archivo real
strings archivo            # Strings legibles dentro del binario
exiftool imagen.png        # Metadatos de imagen

# 2. Si parece un encoding/cifrado → ctf_toolkit.py
python3 scripts/ctf_toolkit.py

# 3. Si es una imagen → buscar datos ocultos
steghide info imagen.jpg
binwalk -e imagen.png
zsteg imagen.png

# 4. Si es un pcap de red → Wireshark
tshark -r captura.pcap -Y "http" -T fields -e http.request.uri

# 5. Si es un binario → analizar
strings binario | grep -i flag
gdb binario
```
