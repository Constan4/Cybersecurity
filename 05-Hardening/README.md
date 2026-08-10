# 05 — Hardening

> **Fase defensiva del ciclo:** aplicar medidas de bastionado para que las técnicas de ataque documentadas en los módulos anteriores no funcionen.

---

## ¿Qué es el hardening?

El hardening (bastionado) es el proceso de reducir la **superficie de ataque** de un sistema eliminando funcionalidades innecesarias, corrigiendo configuraciones por defecto y aplicando controles de seguridad. El objetivo es que cada técnica del ciclo de ataque encuentre una barrera.

```
ATAQUE                          DEFENSA (hardening)
────────────────────────────────────────────────────
Ping Sweep / Nmap          →    Firewall activo + filtro ICMP
Explotación SMB            →    SMBv1 desactivado + puertos cerrados
Payload via macro Word     →    Macros VBA desactivadas por GPO
Meterpreter                →    EDR + Script Block Logging
getsystem / UAC bypass     →    UAC en nivel máximo + parches al día
Persistencia en registro   →    Auditoría de Run Keys + Autoruns
clearev                    →    Sysmon + SIEM con logs centralizados
```

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [hardening-windows.md](apuntes/hardening-windows.md) | Guía completa de bastionado Windows: firewall, Defender, UAC, SMB, macros, PS, BitLocker, ASR |
| [checklist-seguridad.md](apuntes/checklist-seguridad.md) | Checklist pre/post auditoría y baseline de seguridad por categorías |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [hardening_audit.ps1](scripts/hardening_audit.ps1) | Audita el estado de seguridad de un sistema Windows y genera un informe de cumplimiento | `.\hardening_audit.ps1` |

---

## Flujo de trabajo típico

```powershell
# 1. Auditar el estado actual del sistema
.\scripts\hardening_audit.ps1 -OutputDir C:\audit_result

# 2. Revisar el informe generado
Get-Content C:\audit_result\hardening_report.txt

# 3. Aplicar las medidas FALLO → OK manualmente o con el script
#    siguiendo las instrucciones de hardening-windows.md

# 4. Volver a ejecutar la auditoría para verificar mejoras
.\scripts\hardening_audit.ps1 -OutputDir C:\audit_result_v2
```

---

## Marcos de referencia

| Marco | Descripción | URL |
|-------|-------------|-----|
| **CIS Benchmarks** | Guías de configuración segura por SO y aplicación | cisecurity.org |
| **STIG** | Guías del Departamento de Defensa de EE.UU. | public.cyber.mil |
| **NIST SP 800-53** | Controles de seguridad para sistemas federales | csrc.nist.gov |
| **INCIBE** | Guías en español para endpoint Windows | incibe.es |

---

## ⚠️ Nota importante

> El hardening puede interrumpir funcionalidades si no se aplica con criterio.
> Siempre probar en un entorno de pruebas antes de aplicar en producción.
> Documentar cada cambio para poder revertirlo si es necesario.
