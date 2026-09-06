# Puntos de decisión y supervisión

El entorno local puede funcionar sin decisiones adicionales una vez que el
usuario cree `.env`. Los siguientes puntos sí requieren aprobación humana antes
de ampliar el alcance o tratar datos reales.

| Momento | Decisión o insumo | Por qué no se asume |
|---|---|---|
| Primer arranque | Credenciales PostgreSQL, `SECRET_KEY` y administrador | Son secretos personales; no deben enviarse al chat ni incluirse en el ZIP |
| Activar una fuente | Fuente/dataset, términos, cuota y credencial | Puede producir costes, restricciones contractuales o impacto legal |
| Configurar fuentes premium | Claves Shodan, VirusTotal o SecurityTrails cargadas localmente | Codex no debe recibir, generar ni mostrar esas claves |
| Caso real | Finalidad, base legal, jurisdicción y sujetos permitidos | Define qué se puede recolectar y durante cuánto tiempo |
| Producción | Plataforma, dominio, TLS, red, gestor de secretos y observabilidad | Cambia la arquitectura y la superficie de ataque |
| Datos sensibles | Retención, borrado, cifrado, acceso y legal hold | Requiere política organizacional y posiblemente asesoría legal |
| LLM de nube | Proveedor, región, DPA y reglas de redacción | La evidencia podría salir de la infraestructura local |
| Archivos grandes | S3 compatible, antivirus, cifrado y WORM | Introduce infraestructura y cadena de custodia nuevas |
| Identidad corporativa | Proveedor OIDC/SSO, MFA y mapeo de grupos | Afecta login, aprovisionamiento y RBAC |
| Escala/tenancy | Volumen, SLO, RPO/RTO y aislamiento por organización | Puede exigir colas, particionado o multitenancy estricto |
| Publicación | Licencia de software y titularidad | No existe información suficiente para escoger una licencia por el usuario |
| Release productivo | Formato de lock, registro y escáner de dependencias | Depende del CI/CD y de las políticas de suministro de la organización |

## No requiere supervisión adicional

- Ejecutar migraciones y pruebas en una base local desechable.
- Crear proyectos e investigaciones sintéticas.
- Usar DNS/RDAP sobre dominios propios o expresamente autorizados.
- Ejecutar fuentes pasivas públicas sobre blancos expresamente autorizados y
  aceptar el fallback determinista cuando Ollama no esté disponible.
- Usar Ollama local sin enviar evidencia a terceros.

## Información que nunca debe compartirse por chat

No pegues `.env`, contraseñas, JWT, API keys, volcados de base, evidencia real
ni datos personales. Para una integración futura basta indicar el nombre del
proveedor y confirmar que la credencial está cargada en el gestor aprobado.
