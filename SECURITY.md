# 🛡️ Política de Seguridad y Divulgación Coordinada (CVD)

El proyecto **DataCleaner** aplica las directrices de seguridad de software seguro **NIST SSDF (SP 800-218)**, **EO 14028** y las mejores prácticas de cadena de suministro **CNCF Supply Chain Security**.

---

## 📦 Versiones Soportadas

Actualmente se reciben reportes de seguridad y parches correctivos para las siguientes versiones:

| Versión | Estado de Soporte | Nivel de Mantenimiento |
| :--- | :--- | :--- |
| **1.0.x** | ✅ Soportada | Parches de seguridad críticos y correcciones activas |
| **< 1.0.0** | ❌ No soportada | Versiones preliminares / Obsoletas |

---

## 🔒 Reporte Privado de Vulnerabilidades (Coordinated Vulnerability Disclosure - CVD)

Si descubres una vulnerabilidad de seguridad en DataCleaner, **por favor no la expongas públicamente** en issues, pull requests ni foros abiertos.

### Procedimiento de Notificación Responsable:
1. **Contacto Primario**: Envía un correo electrónico a `security@datacleaner.local` o utiliza la función privada de **Security Advisories** de GitHub.
2. **Información Requerida**:
   - Módulo o archivo afectado (ej. `datacleaner/quarantine.py`, `magic.py`, etc.).
   - Descripción detallada del impacto (ej. TOCTOU, Bypass de permisos, evasión forense).
   - Pasos para reproducir el fallo o código de PoC (Proof of Concept).
   - Impacto estimado según CVSS v3.1.
3. **Cifrado PGP**: Para información de alta sensibilidad, puedes cifrar el mensaje con la clave PGP de seguridad del proyecto disponible en el repositorio de gobernanza.

### Compromiso de Respuesta (SLA):
- **Acuse de recibo y triaje inicial**: Menos de **48 horas**.
- **Evaluación y confirmación de severidad**: Menos de **5 días hábiles**.
- **Publicación del parche y aviso de seguridad**: Ventana coordinada de **30 a 90 días** según la criticidad.

---

## ⚙️ Controles de Seguridad Arquitectónicos Implementados

DataCleaner incorpora controles de seguridad rigurosos en su núcleo de ejecución:

1. **Blindaje Anti-TOCTOU a Nivel de Kernel**:
   - Inspección directa sobre descriptores de archivos (`os.fstat(fd)`) con exclusión y bloqueo de kernel (`msvcrt.locking` / `fcntl.flock`), previniendo sustitución en caliente de inodos o enlaces simbólicos.
2. **Inmutabilidad de Evidencias (HMAC-SHA256)**:
   - Los manifiestos de aislamiento (`manifest.json`) se firman criptográficamente generando `manifest.json.sig`. La restauración aborta automáticamente si se detecta cualquier alteración en las rutas de destino.
3. **Auditoría Append-Only (Hash-Chain)**:
   - El historial de operaciones SQLite (`operations_history`) encadena criptográficamente cada registro con el hash de la fila precedente (`prev_hash` y `entry_hash`), detectando cualquier manipulación o borrado manual.
4. **Protección Forense Estricta (Magic Numbers / CWE-434)**:
   - Inspección binaria determinista sin confiar en extensiones. Detección de ejecutables camuflados, accesos directos maliciosos Windows (`.lnk`), scripts HTML/HTA y ataques de inversión visual RTLO (`\u202E`).
5. **Aislamiento de la Cadena de Suministro (CI/CD)**:
   - Dependencias escaneadas mediante `pip-audit` y `cyclonedx-bom`.
   - Acciones de GitHub fijadas a hashes SHA completos inmutables (`pinning`).
   - Bloqueo de rutas protegidas del sistema operativo (`SYSTEM_BLACKLIST`).

---

## 🔑 Gobernanza de Ramas y Firma Criptográfica de Commits

- **Branch Protection en `main`**:
  - Requiere revisión obligatoria y paso satisfactorio del pipeline `Security & Quality Gate`.
  - **Firma Criptográfica Obligatoria**: Se exige que todas las confirmaciones de código (*commits*) hacia la rama `main` estén firmadas digitalmente mediante claves **GPG** o **SSH** verificadas (`git commit -S`), garantizando autenticidad y trazabilidad de autoría (NIST SSDF PS.1).
