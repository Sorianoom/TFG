# services/ (pendiente)

Lógica de servicios reutilizable por el backend:

- **data_service** (fase 2): carga y validación de los JSON de `web/data/`.
- **llm_service / notebooklm_service** (fase 5, NO integrado): preparado para el modo **IA ON**
  con NotebookLM. De momento solo se deja el hueco arquitectónico; no se implementa ni se
  conecta nada todavía.

Principio: el modo **IA OFF** (datos locales) debe funcionar de forma completa sin estos
servicios de IA.
