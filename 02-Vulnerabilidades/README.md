# 02 — Vulnerabilidades

> **Fase 2 del ciclo de auditoría:** identificación, comprensión y priorización de vulnerabilidades conocidas.

---

## ¿Qué es una vulnerabilidad?

Una **vulnerabilidad** es un fallo o debilidad en un sistema que puede ser aprovechado por un atacante para comprometer la confidencialidad, integridad o disponibilidad de la información.

La diferencia clave entre conceptos:

| Concepto | Definición | Ejemplo |
|----------|-----------|---------|
| **Vulnerabilidad** | El fallo en el sistema | Buffer overflow en OpenSSL |
| **Exploit** | El código que aprovecha el fallo | Shellcode para CVE-2014-0160 |
| **Payload** | Lo que ejecuta el exploit | Reverse shell, keylogger |
| **CVE** | El identificador único del fallo | CVE-2014-0160 (Heartbleed) |

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [como-leer-un-cve.md](apuntes/como-leer-un-cve.md) | Anatomía de un CVE, sistema CVSS, bases de datos y ejemplos reales |
| [owasp-top10.md](apuntes/owasp-top10.md) | Las 10 vulnerabilidades web más críticas según OWASP 2021 |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [vuln_checker.py](scripts/vuln_checker.py) | Consulta la API de NVD para buscar CVEs de un software o versión | `python3 vuln_checker.py -k "apache" -v "2.4.49"` |

---

## Flujo de trabajo típico

```bash
# 1. Tras identificar un servicio con Nmap (ej: Apache 2.4.49)
#    buscar sus CVEs en la base de datos NVD

python3 scripts/vuln_checker.py -k "apache httpd" -v "2.4.49" -s HIGH

# 2. Para una auditoría web, revisar si aplica algún OWASP Top 10
#    consultando los apuntes

# 3. Buscar exploits disponibles en Exploit-DB
searchsploit "apache 2.4.49"

# 4. Verificar si el sistema está parcheado
nmap --script=http-vuln-cve2021-41773 -p80 192.168.1.41
```

---

## Bases de datos de vulnerabilidades esenciales

| Base de datos | URL | Descripción |
|---------------|-----|-------------|
| **NVD** | nvd.nist.gov | Base oficial del NIST. Incluye CVSS y CPE |
| **MITRE CVE** | cve.mitre.org | Registro original de CVEs |
| **Exploit-DB** | exploit-db.com | Exploits públicos listos para usar |
| **GitHub Advisory** | github.com/advisories | Vulnerabilidades en paquetes open source |
| **VulDB** | vuldb.com | Base comercial con timeline detallado |
| **CISA KEV** | cisa.gov/kev | CVEs explotados activamente en producción |

---

## ⚠️ Aviso Legal

> Las técnicas y herramientas de este módulo son para uso **exclusivo** en auditorías autorizadas, entornos de laboratorio y formación en ciberseguridad.
