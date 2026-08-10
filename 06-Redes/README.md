# 06 — Redes

> Fundamentos de redes y seguridad inalámbrica: los cimientos técnicos sobre los que se apoya todo el ciclo de auditoría.

---

## ¿Por qué un módulo de redes?

Sin entender cómo funciona la red, no se puede auditar ni proteger. Este módulo cubre los conceptos que aparecen en todos los demás:

- **Módulo 01** usa TCP/IP para el escaneo de puertos
- **Módulo 03** usa TCP para la conexión reversa del payload
- **Módulo 05** usa reglas de firewall por protocolo y puerto
- Y el vector de entrada más frecuente en redes corporativas es el **WiFi**

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [modelo-tcpip.md](apuntes/modelo-tcpip.md) | Modelo OSI vs TCP/IP, puertos, protocolos, three-way handshake |
| [seguridad-wifi.md](apuntes/seguridad-wifi.md) | WPA2/WPA3, captura de handshake, PMKID, Evil Twin, defensa |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [network_mapper.py](scripts/network_mapper.py) | Parsea XML de Nmap y genera mapa visual + informe HTML | `python3 network_mapper.py -i scan.xml` |

---

## Flujo de trabajo

```bash
# 1. Escanear la red y guardar en XML
nmap -sV -sC -O -Pn -oX scan.xml 192.168.1.0/24

# 2. Generar mapa visual en consola
python3 scripts/network_mapper.py -i scan.xml

# 3. Generar informe HTML completo
python3 scripts/network_mapper.py -i scan.xml --html mapa_red.html

# 4. Para auditoría WiFi:
# Poner la tarjeta en modo monitor
sudo airmon-ng start wlan0

# Ver redes cercanas
sudo airodump-ng wlan0mon

# Capturar handshake WPA2
sudo airodump-ng -c CANAL --bssid MAC_AP -w captura wlan0mon

# Forzar reconexión (deauth)
sudo aireplay-ng --deauth 5 -a MAC_AP wlan0mon
```

---

## ⚠️ Aviso Legal

> Las técnicas de auditoría WiFi requieren autorización expresa del propietario de la red.
> Interceptar tráfico de redes ajenas es ilegal en España y en la mayoría de jurisdicciones.
