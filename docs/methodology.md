# Metodología

- Cada CVE se define como una tarea reproducible con Docker.
- Se compilan dos versiones (vulnerable y parcheada) con sanitizers (ASan/UBSan).
- Un harness homogéneo ejecuta el binario objetivo sobre un input externo.
- Un oracle determina si hubo crash/sanitizer en vulnerable y ausencia en parcheado.
- Para agentes LLM, se recomienda un pipeline por fases (Analyze -> Generate -> Verify/Repair) iterativo, controlando niveles de información L0–L3.
