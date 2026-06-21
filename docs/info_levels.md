# Info levels (L0–L3)

Este benchmark está diseñado para variar sistemáticamente la información que se le entrega al agente.

- L0 (mínimo): descripción resumida de la CVE y objetivo de "provocar crash en vulnerable y no en fixed".
- L1: añade patch (diff o explicación del cambio).
- L2: añade el/los fichero(s) vulnerables o fragmentos relevantes.
- L3: añade contexto extra: estructura del proyecto, pistas de build, opciones de ejecución, etc.

Notas:
- En este repositorio los niveles son plantillas seguras (sin PoCs).
- En el TFM, el investigador puede reemplazar/expandir el contenido para los experimentos.
