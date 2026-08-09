# 01 — Reconocimiento

> **Fase 1 del ciclo de auditoría:** recolección de información sobre el objetivo antes de cualquier interacción invasiva.

---

## ¿Qué es el Reconocimiento?

El reconocimiento es el punto de partida de cualquier auditoría de seguridad.
El objetivo es responder a preguntas clave: **¿qué dispositivos hay en la red? ¿qué servicios exponen? ¿qué versiones de software usan?**

Se divide en dos categorías fundamentales:

| Tipo | Descripción | Riesgo de detección |
|------|-------------|---------------------|
| **Pasivo (OSINT)** | Recolección sin interactuar con el objetivo (Google, Shodan, WHOIS...) | Muy bajo |
| **Activo** | Interacción directa: escaneos de red, fingerprinting, banner grabbing | Medio-Alto |

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [nmap-guia-completa.md](apuntes/nmap-guia-completa.md) | Guía completa de Nmap: tipos de escaneo, flags, NSE scripts y ejemplos prácticos |

*Próximamente: OSINT, Fingerprinting, Shodan*

### 🛠️ Scripts

| Script | Descripción | Tecnología |
|--------|-------------|------------|
| [network_recon.py](scripts/network_recon.py) | Herramienta propia: Ping Sweep + Port Scanner + Banner Grabbing + Informe | Python 3 |

---

## Flujo de trabajo típico

```bash
# 1. Descubrimiento de hosts en toda la red (sin escanear puertos)
python3 scripts/network_recon.py -t 192.168.1.0/24 --solo-ping

# 2. Escaneo completo de un host con generación de informe
python3 scripts/network_recon.py -t 192.168.1.41 -p 1-1024 --report

# 3. Escaneo rápido de puertos más comunes
python3 scripts/network_recon.py -t 192.168.1.41 -p 22,80,443,3389,445

# 4. Escaneo avanzado con Nmap (fingerprinting completo)
nmap -sV -sC -O -Pn 192.168.1.41
```

---

## Conceptos clave de esta fase

- **Ping Sweep:** barrido ICMP para identificar qué IPs están activas en un rango de red.
- **Port Scanning:** comprobación de qué puertos TCP/UDP están abiertos en un host.
- **Banner Grabbing:** captura del mensaje de bienvenida de un servicio para identificar su versión.
- **Fingerprinting:** identificación del sistema operativo y versiones de software mediante análisis de respuestas de red.

---

## ⚠️ Aviso Legal

> Todas las técnicas documentadas en este módulo son para uso **exclusivo** en:
> - Entornos de laboratorio propios y controlados
> - Sistemas con **autorización expresa y por escrito** del propietario
> - Contextos educativos y de certificación (CEH, eJPT, OSCP...)
>
> El uso no autorizado en sistemas ajenos puede constituir un **delito penal** (Art. 197 y 264 del Código Penal español).
