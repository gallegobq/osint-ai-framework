# Modos operativos de ciberseguridad

El modo pertenece a cada investigación. Un proyecto puede agrupar casos de los
tres tipos sin ampliar automáticamente los permisos de los demás casos.

| Modo | Objetivo | Política de herramientas |
|---|---|---|
| `attack_surface` | Descubrir, inventariar y seguir exposición externa | Recolección pasiva; es el valor compatible para investigaciones existentes |
| `incident_response` | Enriquecer IOC, ordenar la cronología y preservar evidencia | Recolección pasiva; prioriza contexto, procedencia y tiempo |
| `pentest` | Validar controles dentro de un engagement autorizado | Puede solicitar herramientas activas sólo con alcance, autorización, ventana vigente y confirmación por ejecución |

La primera herramienta activa disponible es una línea base TLS/HTTP aislada.
No equivale a explotación ni a un pentest completo. Consulta
[soc-sandbox.md](soc-sandbox.md) para conocer sus límites y controles.

La interfaz adapta el contexto que recibe Ollama, pero la política no depende
del modelo ni del navegador. La API impide `allow_active=true` fuera de pentest;
el worker vuelve a comprobar el modo, la autorización y la ventana justo antes
de construir el plan. Por tanto, una solicitud almacenada no conserva capacidad
activa después de vencer el engagement.

## Crear un pentest

```json
{
  "title": "Validación externa autorizada",
  "kind": "domain",
  "priority": "high",
  "operation_mode": "pentest",
  "authorization_scope": "Sólo example.com; excluidos correo y proveedores.",
  "active_testing_authorized": true,
  "engagement_start_at": "2026-08-15T14:00:00Z",
  "engagement_end_at": "2026-08-15T20:00:00Z"
}
```

Los timestamps deben incluir zona horaria. El alcance no debe contener
contraseñas, tokens o secretos. El modo es inmutable después de crear el caso;
si cambia la naturaleza del trabajo, crea otra investigación para conservar una
frontera de autorización clara.

Una ejecución activa también requiere `authorization_confirmed=true` y una
`scope_note` específica. Ninguna de estas confirmaciones convierte un objetivo
ajeno en autorizado.

El diseño sigue la separación de objetivos de gestión de riesgo de
[NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20).
Para inteligencia interoperable, la evolución prevista usa
[STIX 2.1](https://www.oasis-open.org/standard/stix-version-2-1/) y el catálogo
[MITRE ATT&CK](https://attack.mitre.org/resources/attack-data-and-tools/).
