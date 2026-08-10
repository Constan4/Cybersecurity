# Modelo TCP/IP y Protocolos de Red — Guía Completa

> Los fundamentos de red que aparecen en cada herramienta del ciclo de auditoría: desde el escaneo Nmap hasta la conexión reversa de Meterpreter.

---

## Tabla de contenidos

1. [Modelo OSI vs TCP/IP](#1-modelo-osi-vs-tcpip)
2. [El protocolo TCP en detalle](#2-el-protocolo-tcp-en-detalle)
3. [UDP — Cuándo y por qué](#3-udp--cuándo-y-por-qué)
4. [Puertos — El mapa del servicio](#4-puertos--el-mapa-del-servicio)
5. [Protocolos clave para auditorías](#5-protocolos-clave-para-auditorías)
6. [Direccionamiento IP y subredes](#6-direccionamiento-ip-y-subredes)
7. [Comandos de red esenciales](#7-comandos-de-red-esenciales)
8. [Cheat Sheet](#8-cheat-sheet)

---

## 1. Modelo OSI vs TCP/IP

### El modelo OSI (teórico, 7 capas)

```
┌─────────────────────────────────────────────────────────────┐
│  CAPA  │  NOMBRE        │  FUNCIÓN                │ EJEMPLO │
├────────┼────────────────┼─────────────────────────┼─────────┤
│   7    │ Aplicación     │ Interfaz con el usuario  │ HTTP    │
│   6    │ Presentación   │ Cifrado, compresión      │ TLS/SSL │
│   5    │ Sesión         │ Control de sesiones      │ NetBIOS │
│   4    │ Transporte     │ Segmentación, fiabilidad │ TCP/UDP │
│   3    │ Red            │ Enrutamiento de paquetes │ IP      │
│   2    │ Enlace datos   │ Tramas, MAC              │ Ethernet│
│   1    │ Física         │ Señales eléctricas/óptic │ Cable   │
└─────────────────────────────────────────────────────────────┘
```

### El modelo TCP/IP (práctico, 4 capas)

```
┌──────────────────────────────────────────────────────────┐
│  CAPA TCP/IP     │  Capas OSI equivalentes  │  Protocolos│
├──────────────────┼──────────────────────────┼────────────┤
│ Aplicación       │ 7 + 6 + 5                │ HTTP,DNS,  │
│                  │                          │ SSH,FTP,   │
│                  │                          │ SMTP,SMB   │
├──────────────────┼──────────────────────────┼────────────┤
│ Transporte       │ 4                        │ TCP, UDP   │
├──────────────────┼──────────────────────────┼────────────┤
│ Internet         │ 3                        │ IP,ICMP,   │
│                  │                          │ ARP        │
├──────────────────┼──────────────────────────┼────────────┤
│ Acceso a red     │ 2 + 1                    │ Ethernet,  │
│                  │                          │ WiFi,PPP   │
└──────────────────────────────────────────────────────────┘
```

> **Regla práctica para auditorías:** Nmap trabaja en capas 3 y 4. Los exploits suelen trabajar en capa 7 (aplicación). Los ataques WiFi trabajan en capa 2.

---

## 2. El protocolo TCP en detalle

### Three-Way Handshake — El apretón de manos

TCP establece conexiones mediante un intercambio de tres mensajes. Entender esto explica por qué los diferentes tipos de escaneo de Nmap funcionan como funcionan.

```
CLIENTE (Nmap / atacante)          SERVIDOR (objetivo)
         │                                  │
         │──────── SYN ────────────────────►│  "¿Podemos hablar?"
         │         (Seq=X)                  │
         │                                  │
         │◄──── SYN + ACK ─────────────────│  "Sí, yo también quiero"
         │      (Seq=Y, Ack=X+1)            │
         │                                  │
         │──────── ACK ────────────────────►│  "Confirmado, hablemos"
         │         (Ack=Y+1)                │
         │                                  │
         │    [Conexión establecida]         │
```

### Flags TCP y qué significan

| Flag | Nombre | Cuándo se usa |
|------|--------|---------------|
| `SYN` | Synchronize | Inicio de conexión |
| `ACK` | Acknowledge | Confirmación de recepción |
| `RST` | Reset | Rechazo o cierre abrupto |
| `FIN` | Finish | Cierre ordenado de conexión |
| `PSH` | Push | Enviar datos inmediatamente |
| `URG` | Urgent | Datos prioritarios |

### Cómo usa Nmap los flags

```
SYN Scan (-sS):
Nmap → SYN → servidor
Puerto ABIERTO:  servidor → SYN+ACK → Nmap → RST (no completa)
Puerto CERRADO:  servidor → RST
Puerto FILTRADO: sin respuesta (firewall descarta)

Connect Scan (-sT):
Nmap completa el handshake completo (menos sigiloso)

ACK Scan (-sA):
Nmap → ACK → servidor
Sin regla de firewall: servidor → RST (unfiltered)
Con firewall:          sin respuesta (filtered)
```

### El flujo completo de Meterpreter

```
KALI (handler en 4444)          VÍCTIMA (payload ejecutado)
         │                              │
         │◄─── SYN ────────────────────│  El payload inicia la conexión
         │──── SYN+ACK ───────────────►│
         │◄─── ACK ────────────────────│
         │◄─── [Stage descarga] ───────│  Stager descarga Meterpreter
         │──── [Meterpreter DLL] ──────►│  Kali envía el stage
         │◄════════════════════════════│  Sesión cifrada establecida
         │  [Comandos bidireccionales]  │
```

---

## 3. UDP — Cuándo y por qué

UDP no tiene three-way handshake. Simplemente envía datos sin confirmar recepción.

```
EMISOR                    RECEPTOR
  │──── Datagrama ────────►│
  │  (sin confirmación)    │
```

**Servicios UDP críticos para auditorías:**

| Puerto | Servicio | Relevancia en auditorías |
|--------|---------|--------------------------|
| 53 | DNS | Transferencias de zona, DNS poisoning |
| 67/68 | DHCP | DHCP starvation, rogue DHCP |
| 69 | TFTP | Sin autenticación, transferencia de archivos |
| 123 | NTP | NTP amplification DDoS |
| 161 | SNMP | Community strings por defecto (public/private) |
| 500 | IKE/IPSec | VPN, puede revelar configuración |
| 1194 | OpenVPN | |

**Cómo escanear UDP con Nmap:**
```bash
# UDP scan (lento pero necesario)
sudo nmap -sU -p 53,67,68,69,123,161 192.168.1.41

# Combinar TCP y UDP en un solo escaneo
sudo nmap -sS -sU -p T:80,443,445,U:53,161 192.168.1.41
```

---

## 4. Puertos — El mapa del servicio

### Rangos de puertos

```
0     – 1023   → Well-Known Ports (servicios del sistema, requieren root/admin)
1024  – 49151  → Registered Ports (aplicaciones registradas en IANA)
49152 – 65535  → Dynamic/Private Ports (conexiones cliente efímeras)
```

### Puertos críticos en auditorías Windows

| Puerto | Protocolo | Servicio | Riesgo si está expuesto |
|--------|-----------|---------|--------------------------|
| 21 | TCP | FTP | Credenciales en texto plano, anonymous login |
| 22 | TCP | SSH | Fuerza bruta si contraseña débil |
| 23 | TCP | Telnet | Todo en texto plano (obsoleto) |
| 25 | TCP | SMTP | Open relay, spam, enumeración |
| 53 | TCP/UDP | DNS | Transferencia de zona, amplificación |
| 80 | TCP | HTTP | Aplicaciones web sin cifrar |
| 110 | TCP | POP3 | Credenciales de email en texto plano |
| 135 | TCP | MSRPC | Vector de explotación Windows |
| 139 | TCP | NetBIOS | Enumeración SMB, passthroughs |
| 143 | TCP | IMAP | Credenciales en texto plano |
| 443 | TCP | HTTPS | Aplicaciones web (certificados, TLS) |
| **445** | TCP | **SMB** | **EternalBlue, Pass-the-Hash, relay attacks** |
| 1433 | TCP | MSSQL | BD SQL Server, credenciales por defecto |
| 3306 | TCP | MySQL | BD sin autenticación remota |
| **3389** | TCP | **RDP** | **Fuerza bruta, BlueKeep (CVE-2019-0708)** |
| 5432 | TCP | PostgreSQL | BD PostgreSQL |
| 5900 | TCP | VNC | Sin contraseña o contraseña débil |
| 6379 | TCP | Redis | Sin autenticación por defecto |
| 8080 | TCP | HTTP-Alt | Paneles de admin, Tomcat |
| 27017 | TCP | MongoDB | Sin autenticación por defecto |

---

## 5. Protocolos clave para auditorías

### DNS — Sistema de Nombres de Dominio

```bash
# Resolución normal
nslookup ejemplo.com
dig ejemplo.com A

# Transferencia de zona (si el servidor lo permite)
dig @dns.ejemplo.com ejemplo.com AXFR

# Enumeración de subdominios
host -t mx ejemplo.com    # Servidores de correo
host -t ns ejemplo.com    # Servidores DNS autoritativos

# Reverse lookup
dig -x 192.168.1.41
```

---

### DHCP — Asignación dinámica de IPs

```
CLIENTE                              SERVIDOR DHCP
   │──── DISCOVER (broadcast) ──────►│  "¿Hay algún servidor DHCP?"
   │◄─── OFFER ──────────────────────│  "Toma la IP 192.168.1.50"
   │──── REQUEST (broadcast) ────────►│  "Quiero esa IP"
   │◄─── ACK ────────────────────────│  "Confirmado, es tuya"
```

**Ataques DHCP:**
- **DHCP Starvation:** solicitar todas las IPs disponibles hasta agotar el pool
- **Rogue DHCP:** levantar un servidor DHCP falso que asigne nuestra IP como gateway → MitM

---

### ARP — Resolución de direcciones IP a MAC

ARP resuelve IPs a direcciones MAC en la red local. Sin autenticación.

```bash
# Ver tabla ARP local
arp -a          # Windows
arp -n          # Linux

# ARP Spoofing (herramienta arpspoof de dsniff)
# Hacer que la víctima crea que somos el router:
sudo arpspoof -i eth0 -t 192.168.1.41 192.168.1.1
# Hacer que el router crea que somos la víctima:
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.41
```

---

### SMB — Server Message Block

Protocolo de compartición de archivos e impresoras en Windows. El más auditado en entornos corporativos.

```bash
# Versiones: SMBv1 (obsoleto, vulnerable), SMBv2, SMBv3 (con cifrado)

# Enumeración con Nmap
nmap -sV -p 445 --script=smb-security-mode,smb2-security-mode 192.168.1.41
nmap -p 445 --script=smb-enum-shares 192.168.1.41
nmap -p 445 --script=smb-vuln-ms17-010 192.168.1.41

# Conectar a un share (Linux)
smbclient \\\\192.168.1.41\\ADMIN$ -U Administrator
smbclient -L 192.168.1.41 -N   # Listar shares anónimamente
```

---

### ICMP — Control y diagnóstico

El protocolo del `ping`. Nmap lo usa para el host discovery.

```bash
# Ping básico
ping 192.168.1.41

# Traceroute (Linux)
traceroute 192.168.1.41

# Tracert (Windows)
tracert 192.168.1.41

# El firewall de Windows bloquea ICMP por defecto
# Por eso Nmap necesita -Pn en sistemas Windows modernos
```

---

## 6. Direccionamiento IP y subredes

### Clases de IP privadas (RFC 1918)

```
Clase A:  10.0.0.0   – 10.255.255.255   /8   (16.7 millones de hosts)
Clase B:  172.16.0.0 – 172.31.255.255   /12  (1 millón de hosts)
Clase C:  192.168.0.0– 192.168.255.255  /16  (65.536 hosts)
```

### Notación CIDR — Cálculo rápido

| CIDR | Máscara | Hosts útiles | Uso típico |
|------|---------|--------------|------------|
| /24 | 255.255.255.0 | 254 | Red de empresa pequeña |
| /25 | 255.255.255.128 | 126 | División de /24 |
| /16 | 255.255.0.0 | 65.534 | Red de empresa grande |
| /30 | 255.255.255.252 | 2 | Enlace punto a punto |
| /32 | 255.255.255.255 | 1 | Host único |

```bash
# Calcular hosts en un rango desde Nmap
nmap -sn 192.168.1.0/24   # Escanea los 254 hosts del rango /24

# Calcular hosts manualmente:
# Hosts = 2^(32-CIDR) - 2
# /24 → 2^8 - 2 = 254 hosts
# /25 → 2^7 - 2 = 126 hosts
```

---

## 7. Comandos de red esenciales

### Windows

```powershell
# Ver interfaces y IPs
ipconfig /all

# Ver tabla ARP
arp -a

# Ver conexiones activas
netstat -ano                        # Todas las conexiones con PID
netstat -ano | findstr :4444        # Buscar una conexión específica
netstat -b                          # Con nombre del proceso (requiere admin)

# Ver tabla de rutas
route print

# Resolver un nombre
nslookup nombre.local
Resolve-DnsName nombre.local

# Comprobar si un puerto está abierto
Test-NetConnection 192.168.1.41 -Port 445
```

### Linux

```bash
# Ver interfaces
ip addr
ip a

# Ver tabla ARP
ip neigh
arp -n

# Ver conexiones activas
ss -tulpn         # Puertos en escucha
ss -antp          # Todas las conexiones TCP con PID
netstat -tulpn    # Alternativa

# Ver tabla de rutas
ip route
route -n

# Escanear puerto rápidamente (sin Nmap)
nc -zv 192.168.1.41 445   # TCP
timeout 1 bash -c "cat < /dev/tcp/192.168.1.41/80" && echo "abierto"

# Captura de paquetes
sudo tcpdump -i eth0 -w captura.pcap
sudo tcpdump -i eth0 port 80 -A   # HTTP en texto plano
```

---

## 8. Cheat Sheet

```
══════════════════════════════════════════════════════════════
              REDES Y PROTOCOLOS — CHEAT SHEET
══════════════════════════════════════════════════════════════

FLAGS TCP
  SYN          → Inicio de conexión
  SYN+ACK      → Respuesta del servidor (puerto abierto)
  RST          → Puerto cerrado o rechazo
  FIN          → Cierre ordenado
  ACK          → Confirmación

ESTADOS DE PUERTO (Nmap)
  open         → Puerto abierto con servicio escuchando
  closed       → Accesible pero sin servicio
  filtered     → Firewall descarta los paquetes (no responde)

RANGOS DE PUERTOS
  0-1023       → Well-Known (sistema)
  1024-49151   → Registered (aplicaciones)
  49152-65535  → Dynamic (clientes)

PUERTOS CRÍTICOS
  21 FTP  22 SSH  23 Telnet  25 SMTP  53 DNS
  80 HTTP  135/139/445 SMB  443 HTTPS
  1433 MSSQL  3306 MySQL  3389 RDP  5900 VNC

IPs PRIVADAS (RFC 1918)
  10.0.0.0/8    172.16.0.0/12    192.168.0.0/16

COMANDOS ÚTILES
  arp -a                   → Tabla ARP (vecinos de red)
  netstat -ano             → Conexiones activas con PID
  ip route / route print   → Tabla de rutas
  nslookup / dig           → Resolución DNS
  tcpdump / Wireshark      → Captura de paquetes

CÁLCULO CIDR
  /24 → 254 hosts    /25 → 126 hosts
  /16 → 65534 hosts  /30 → 2 hosts

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [RFC 793 — Transmission Control Protocol](https://tools.ietf.org/html/rfc793)
- [RFC 1918 — Direcciones IP privadas](https://tools.ietf.org/html/rfc1918)
- [IANA — Lista de puertos registrados](https://www.iana.org/assignments/service-names-port-numbers)
- [Wireshark Protocol Reference](https://wiki.wireshark.org/ProtocolReference)
