# Nmap — Guía Completa

> **Nmap** (Network Mapper) es la herramienta estándar de la industria para el descubrimiento de redes y auditorías de seguridad. Es open source, multiplataforma y viene preinstalada en Kali Linux.

---

## Tabla de contenidos

1. [¿Qué es Nmap y cómo funciona?](#1-qué-es-nmap-y-cómo-funciona)
2. [Instalación](#2-instalación)
3. [Conceptos previos clave](#3-conceptos-previos-clave)
4. [Descubrimiento de hosts](#4-descubrimiento-de-hosts)
5. [Tipos de escaneo de puertos](#5-tipos-de-escaneo-de-puertos)
6. [Detección de versiones y sistema operativo](#6-detección-de-versiones-y-sistema-operativo)
7. [Control de velocidad e intensidad](#7-control-de-velocidad-e-intensidad)
8. [NSE — Nmap Scripting Engine](#8-nse--nmap-scripting-engine)
9. [Formatos de salida](#9-formatos-de-salida)
10. [Especificación de puertos y objetivos](#10-especificación-de-puertos-y-objetivos)
11. [Ejemplos prácticos por escenario](#11-ejemplos-prácticos-por-escenario)
12. [Cheat Sheet](#12-cheat-sheet)

---

## 1. ¿Qué es Nmap y cómo funciona?

Nmap funciona enviando **paquetes de red cuidadosamente construidos** a los hosts objetivo y analizando las respuestas. A partir de esas respuestas (o la ausencia de ellas), puede determinar:

- Qué hosts están activos en una red
- Qué puertos tienen abiertos
- Qué servicios y versiones están corriendo
- Qué sistema operativo está usando el host
- Si existen vulnerabilidades conocidas (mediante scripts)

### Fases de un escaneo Nmap

```
1. Resolución DNS      → Convierte nombres de dominio a IPs
2. Ping (host discovery) → Comprueba si el host está activo
3. Port scanning       → Determina el estado de los puertos
4. Version detection   → Identifica el servicio en cada puerto
5. OS detection        → Determina el sistema operativo
6. Traceroute          → Mapea la ruta de red hasta el objetivo
7. Script scanning     → Ejecuta scripts NSE adicionales
```

---

## 2. Instalación

```bash
# Kali Linux / Debian / Ubuntu
sudo apt install nmap

# macOS (con Homebrew)
brew install nmap

# Windows
# Descargar el instalador desde https://nmap.org/download.html

# Verificar instalación
nmap --version
```

---

## 3. Conceptos previos clave

### Estados de un puerto en Nmap

| Estado | Significado |
|--------|-------------|
| `open` | El puerto acepta conexiones. Hay un servicio escuchando. |
| `closed` | El puerto es accesible pero no hay servicio escuchando. |
| `filtered` | Nmap no puede determinar si está abierto. Un firewall descarta los paquetes. |
| `unfiltered` | El puerto es accesible pero Nmap no puede determinar si está abierto o cerrado. |
| `open\|filtered` | No puede distinguir entre abierto y filtrado (típico en UDP). |
| `closed\|filtered` | No puede distinguir entre cerrado y filtrado. |

### El Three-Way Handshake (TCP)

Entender cómo funciona TCP es esencial para comprender los distintos tipos de escaneo:

```
Cliente          Servidor
   |                |
   |--- SYN ------->|   (1) Cliente solicita conexión
   |<-- SYN/ACK ----|   (2) Servidor acepta
   |--- ACK ------->|   (3) Conexión establecida
   |                |
```

> Cuando el puerto está **cerrado**, el servidor responde con un **RST** en lugar de SYN/ACK.
> Cuando el puerto está **filtrado**, no hay respuesta (el firewall descarta el paquete).

---

## 4. Descubrimiento de hosts

Antes de escanear puertos, Nmap necesita saber si el host está activo.

### Ping Sweep — Descubrir hosts activos en una red

```bash
# Descubrir todos los hosts activos en una red /24
nmap -sn 192.168.1.0/24

# -sn: "solo ping", no escanea puertos
# Resultado: lista de IPs activas con sus MACs y fabricantes
```

**¿Qué hace `-sn` internamente?**
- Envía un **ICMP Echo Request** (ping clásico)
- Envía un paquete **TCP SYN** al puerto 443
- Envía un paquete **TCP ACK** al puerto 80
- Envía un **ICMP Timestamp Request**

Si el host responde a cualquiera de esos, se considera activo.

### Omitir el descubrimiento (host assumption)

```bash
# Asumir que el host está activo sin hacer ping
nmap -Pn 192.168.1.41

# Cuándo usarlo:
# - El firewall bloquea ICMP (muy común en Windows)
# - Sabemos que el host está activo pero no responde al ping
# - En auditorías donde el ping sweep ya se hizo antes
```

> **⚠️ Importante:** En sistemas Windows modernos, el firewall bloquea el ICMP por defecto.
> Si haces un escaneo sin `-Pn`, Nmap puede creer que el host está caído cuando en realidad está activo.

### Tipos de pruebas de host (avanzado)

```bash
# TCP SYN Ping (a un puerto específico)
nmap -PS22,80,443 192.168.1.41

# TCP ACK Ping
nmap -PA80,443 192.168.1.41

# UDP Ping
nmap -PU53,161 192.168.1.41

# ICMP Ping (solo echo)
nmap -PE 192.168.1.41
```

---

## 5. Tipos de escaneo de puertos

### TCP SYN Scan (-sS) — El más usado

```bash
sudo nmap -sS 192.168.1.41
```

**¿Cómo funciona?**

```
Nmap          Objetivo
  |--- SYN -------->|    (1) Envía SYN
  |<-- SYN/ACK -----|    (2) Puerto ABIERTO → Nmap envía RST (no completa la conexión)
  |--- RST -------->|    (3) Corta la conexión antes de completarla
```

**Ventajas:**
- Rápido (no completa el handshake)
- Menos logs en el sistema objetivo (la conexión no se registra como establecida)
- El más sigiloso de los escaneos TCP

**Desventajas:**
- Requiere privilegios de root/administrador

---

### TCP Connect Scan (-sT) — Sin privilegios

```bash
nmap -sT 192.168.1.41
```

**¿Cómo funciona?**
Completa el three-way handshake completo. Es lo que hace cualquier aplicación normal al conectarse.

**Cuándo usarlo:**
- Cuando no tienes privilegios de root
- Cuando el -sS no funciona correctamente

**Desventajas:**
- Más lento que -sS
- Deja registros completos en los logs del objetivo
- Más fácil de detectar por sistemas IDS/IPS

---

### UDP Scan (-sU) — Para servicios UDP

```bash
sudo nmap -sU 192.168.1.41
sudo nmap -sU -p 53,67,68,69,123,161,162 192.168.1.41
```

**Servicios UDP importantes:**
- **53** → DNS
- **67/68** → DHCP
- **69** → TFTP
- **123** → NTP
- **161** → SNMP (muy jugoso en auditorías)

**¿Por qué es especial?**
UDP no tiene three-way handshake. Si el puerto está abierto, no hay respuesta. Solo si está **cerrado** se recibe un mensaje ICMP "port unreachable".

> **⚠️ UDP es muy lento.** Combínalo con `-T4` y escanea solo los puertos clave.

---

### TCP ACK Scan (-sA) — Mapear firewalls

```bash
sudo nmap -sA 192.168.1.41
```

**¿Para qué sirve?**
No determina si el puerto está abierto o cerrado, sino si está **filtrado o no filtrado**. Sirve para mapear las reglas de un firewall.

- Si responde con **RST** → `unfiltered` (el firewall permite pasar el paquete)
- Si no hay respuesta → `filtered` (el firewall descarta el paquete)

---

### Comparativa de tipos de escaneo

| Tipo | Flag | Requiere root | Velocidad | Sigilo | Uso típico |
|------|------|--------------|-----------|--------|------------|
| TCP SYN | `-sS` | Sí | ★★★★★ | ★★★★ | Escaneo estándar |
| TCP Connect | `-sT` | No | ★★★ | ★★ | Sin privilegios |
| UDP | `-sU` | Sí | ★ | ★★★ | Servicios UDP |
| TCP ACK | `-sA` | Sí | ★★★★ | ★★★ | Mapeo de firewall |

---

## 6. Detección de versiones y sistema operativo

### Detección de versiones de servicios (-sV)

```bash
nmap -sV 192.168.1.41

# Ejemplo de resultado:
# 80/tcp  open  http     Apache httpd 2.4.52 ((Ubuntu))
# 22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
```

**¿Por qué es crítico esto?**
Saber la versión exacta de un servicio permite buscar CVEs (vulnerabilidades conocidas) para esa versión específica. Un Apache 2.4.49, por ejemplo, tiene el CVE-2021-41773 (Path Traversal crítico).

**Nivel de intensidad de detección:**
```bash
# Intensidad de 0 (mínima) a 9 (máxima). Por defecto: 7
nmap -sV --version-intensity 9 192.168.1.41
```

---

### Detección de sistema operativo (-O)

```bash
sudo nmap -O 192.168.1.41

# Ejemplo de resultado:
# OS details: Windows 11 21H2, Linux 5.4 - 5.11
```

**¿Cómo funciona?**
Analiza pequeñas diferencias en cómo los distintos sistemas operativos implementan el protocolo TCP/IP (tamaño de ventana, valores TTL, flags, etc.). A esto se le llama **TCP/IP fingerprinting**.

> **Truco:** Si Nmap no puede determinar el OS, usa `-O --osscan-guess` para que haga una estimación.

---

### Escaneo agresivo (-A)

```bash
nmap -A 192.168.1.41

# Equivale a: -sV -O -sC --traceroute
# Hace todo a la vez: versiones, OS, scripts por defecto y traceroute
```

**¿Cuándo usarlo?**
Cuando quieres la información más completa posible en un solo comando. Es más ruidoso pero muy completo.

---

## 7. Control de velocidad e intensidad

Nmap tiene 6 plantillas de tiempo que controlan la velocidad del escaneo:

| Template | Nombre | Descripción | Cuándo usarla |
|----------|--------|-------------|---------------|
| `-T0` | Paranoid | Espera 5 minutos entre sondas | Evadir IDS (muy lento) |
| `-T1` | Sneaky | Espera 15 segundos entre sondas | Evadir IDS |
| `-T2` | Polite | Reduce la carga en la red | Redes lentas o congestionadas |
| `-T3` | Normal | Por defecto | Uso general |
| `-T4` | Aggressive | Asume red rápida y fiable | Redes LAN o laboratorios |
| `-T5` | Insane | Máxima velocidad, puede perder resultados | Redes muy rápidas (puede dar falsos negativos) |

```bash
# Para laboratorio o red local (recomendado)
nmap -T4 192.168.1.0/24

# Para producción (más cuidadoso)
nmap -T2 192.168.1.0/24
```

---

## 8. NSE — Nmap Scripting Engine

El **NSE** es uno de los componentes más potentes de Nmap. Permite ejecutar scripts Lua para automatizar tareas de reconocimiento, detección de vulnerabilidades e incluso explotación básica.

Los scripts se encuentran en `/usr/share/nmap/scripts/`

### Categorías de scripts

| Categoría | Descripción |
|-----------|-------------|
| `auth` | Detecta credenciales por defecto o sin autenticación |
| `broadcast` | Descubrimiento mediante broadcast en la red |
| `brute` | Ataques de fuerza bruta a servicios |
| `default` | Los ejecutados con `-sC` (seguros y útiles) |
| `discovery` | Enumeración de información del objetivo |
| `exploit` | Intentos de explotación (¡usar con cuidado!) |
| `fuzzer` | Envío de datos inesperados para detectar errores |
| `intrusive` | Scripts intrusivos que pueden causar impacto |
| `safe` | Scripts seguros que no dañan el objetivo |
| `vuln` | Detección de vulnerabilidades conocidas |

### Uso básico

```bash
# Ejecutar los scripts por defecto (categoría "default")
nmap -sC 192.168.1.41

# Ejecutar un script específico
nmap --script=http-title 192.168.1.41

# Ejecutar una categoría completa
nmap --script=vuln 192.168.1.41

# Ejecutar varios scripts
nmap --script=smb-vuln-ms17-010,smb-security-mode 192.168.1.41

# Buscar scripts disponibles
ls /usr/share/nmap/scripts/ | grep smb
```

### Scripts esenciales que debes conocer

```bash
# ── SMB (Windows) ─────────────────────────────────────────────
# Detectar si es vulnerable a EternalBlue (MS17-010)
nmap --script=smb-vuln-ms17-010 -p445 192.168.1.41

# Información de SMB y seguridad
nmap --script=smb-security-mode,smb2-security-mode -p445 192.168.1.41

# ── HTTP ──────────────────────────────────────────────────────
# Título de la página web
nmap --script=http-title -p80,443,8080 192.168.1.41

# Métodos HTTP permitidos
nmap --script=http-methods -p80,443 192.168.1.41

# Detectar CMS (WordPress, Joomla, Drupal)
nmap --script=http-cms-detect -p80,443 192.168.1.41

# ── FTP ───────────────────────────────────────────────────────
# Detectar si FTP permite acceso anónimo
nmap --script=ftp-anon -p21 192.168.1.41

# ── SSH ───────────────────────────────────────────────────────
# Algoritmos de cifrado soportados por SSH
nmap --script=ssh2-enum-algos -p22 192.168.1.41

# ── Base de datos ─────────────────────────────────────────────
# Información de MySQL sin autenticación
nmap --script=mysql-info -p3306 192.168.1.41

# ── Vulnerabilidades ──────────────────────────────────────────
# Escaneo general de vulnerabilidades (¡puede ser ruidoso!)
nmap --script=vuln 192.168.1.41
```

---

## 9. Formatos de salida

Nmap puede guardar los resultados en varios formatos para procesarlos después:

```bash
# Normal (legible por humanos, igual que la pantalla)
nmap -oN resultado.txt 192.168.1.41

# XML (para procesarlo con herramientas como Metasploit o parsers)
nmap -oX resultado.xml 192.168.1.41

# Grepable (una línea por host, fácil de procesar con grep/awk)
nmap -oG resultado.gnmap 192.168.1.41

# Todos los formatos a la vez (recomendado en auditorías)
nmap -oA resultado_completo 192.168.1.41
# Genera: resultado_completo.nmap, resultado_completo.xml, resultado_completo.gnmap
```

### Truco: extraer información del formato grepable

```bash
# Listar solo los hosts activos del resultado grepable
grep "Up" resultado_completo.gnmap | awk '{print $2}'

# Listar hosts con el puerto 80 abierto
grep "80/open" resultado_completo.gnmap
```

---

## 10. Especificación de puertos y objetivos

### Especificar puertos

```bash
# Puerto específico
nmap -p 80 192.168.1.41

# Varios puertos
nmap -p 22,80,443,3389 192.168.1.41

# Rango de puertos
nmap -p 1-1024 192.168.1.41

# Puertos más comunes (top 100)
nmap --top-ports 100 192.168.1.41

# Todos los puertos (1-65535)
nmap -p- 192.168.1.41

# Todos los puertos (forma corta)
nmap -p 0- 192.168.1.41
```

### Especificar objetivos

```bash
# IP única
nmap 192.168.1.41

# Rango CIDR completo
nmap 192.168.1.0/24

# Rango de IPs
nmap 192.168.1.1-50

# Lista de IPs desde archivo
nmap -iL objetivos.txt

# Excluir una IP del rango
nmap 192.168.1.0/24 --exclude 192.168.1.1

# Excluir desde archivo
nmap 192.168.1.0/24 --excludefile excluidos.txt

# Nombre de dominio
nmap ejemplo.com
```

---

## 11. Ejemplos prácticos por escenario

### Escenario 1: Primera vez en una red desconocida

```bash
# Paso 1: ¿Qué hay en la red?
nmap -sn 192.168.1.0/24

# Paso 2: ¿Qué puertos comunes tiene el objetivo identificado?
nmap -T4 --top-ports 200 -Pn 192.168.1.41

# Paso 3: Información detallada del objetivo
nmap -sV -sC -O -Pn 192.168.1.41
```

---

### Escenario 2: Auditoría de un servidor web

```bash
# Escaneo específico para servicios web
nmap -sV -p 80,443,8080,8443 \
     --script=http-title,http-methods,http-headers,http-cms-detect \
     192.168.1.41
```

---

### Escenario 3: Auditoría de un servidor Windows

```bash
# Identificar servicios Windows típicos
nmap -sV -sC -p 135,139,445,3389 \
     --script=smb-security-mode,smb2-security-mode,smb-vuln-ms17-010 \
     -Pn 192.168.1.41
```

---

### Escenario 4: Escaneo sigiloso (evadir IDS básicos)

```bash
# Muy lento pero genera menos alertas
sudo nmap -sS -T1 -f --data-length 25 \
     --script=default 192.168.1.41

# -f: fragmenta los paquetes (dificulta la inspección DPI)
# --data-length 25: añade datos aleatorios para evitar firmas conocidas
# -T1: velocidad muy baja
```

---

### Escenario 5: Escaneo completo de producción (auditoría formal)

```bash
# Escaneo completo con todos los formatos de salida
sudo nmap -sS -sV -sC -O \
     -p- \
     -T4 \
     --open \
     -oA auditoria_$(date +%Y%m%d) \
     192.168.1.41

# --open: mostrar solo puertos abiertos
# -oA: guardar en todos los formatos
```

---

## 12. Cheat Sheet

```
══════════════════════════════════════════════════════════════
                    NMAP CHEAT SHEET
══════════════════════════════════════════════════════════════

DESCUBRIMIENTO DE HOSTS
  nmap -sn 192.168.1.0/24          Ping sweep (sin escaneo de puertos)
  nmap -Pn 192.168.1.41            Asumir host activo (saltar ping)

TIPOS DE ESCANEO
  nmap -sS IP                      TCP SYN (stealth, requiere root)
  nmap -sT IP                      TCP Connect (sin root)
  nmap -sU IP                      UDP Scan
  nmap -sA IP                      TCP ACK (mapear firewall)

PUERTOS
  nmap -p 80                       Puerto específico
  nmap -p 22,80,443                Varios puertos
  nmap -p 1-1024                   Rango
  nmap -p-                         Todos los puertos
  nmap --top-ports 100             Los 100 más comunes

DETECCIÓN
  nmap -sV IP                      Versiones de servicios
  nmap -O IP                       Sistema operativo
  nmap -A IP                       Agresivo (sV + O + sC + traceroute)

VELOCIDAD
  nmap -T0 a -T5                   Plantillas de tiempo (0=lento, 5=rápido)
  nmap -T4                         Recomendado para laboratorio

NSE SCRIPTS
  nmap -sC IP                      Scripts por defecto
  nmap --script=vuln IP            Vulnerabilidades
  nmap --script=smb-vuln-ms17-010  EternalBlue
  nmap --script=ftp-anon           FTP anónimo
  nmap --script=http-title         Título web

SALIDA
  nmap -oN archivo.txt             Formato normal
  nmap -oX archivo.xml             Formato XML
  nmap -oG archivo.gnmap           Formato grepable
  nmap -oA nombre_base             Todos los formatos

COMBINACIONES ÚTILES
  nmap -sV -sC -O -Pn IP          Escaneo completo estándar
  nmap -sS -T4 -p- IP             Todos los puertos, rápido
  nmap -sS -T4 --open -oA out IP  Solo puertos abiertos con salida completa

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [Documentación oficial de Nmap](https://nmap.org/docs.html)
- [Nmap Network Scanning (libro oficial)](https://nmap.org/book/)
- [MITRE ATT&CK — T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [Nmap NSE Scripts Reference](https://nmap.org/nsedoc/)
