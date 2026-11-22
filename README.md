# Gestión de Riesgos ISI604 · Matriz de riesgos conciliada con ISO/IEC 27001:2022

Aplicación web para que los estudiantes de Ingeniería en Desarrollo Informático estudien los contenidos del módulo, construyan la matriz de riesgos de su proyecto y verifiquen su conformidad con las cláusulas 6.1.2, 6.1.3, 8.2, 8.3, 9.1 y 10.2 de la norma y con el Anexo A.

## Estructura

```
riesgos-iso27001/
├── backend/
│   ├── app.py            API REST (FastAPI + SQLite) y servidor del frontend
│   ├── contenido.json    Contenidos de las unidades, escalas, cláusulas 4 a 10 y 93 controles del Anexo A
│   └── requirements.txt
└── frontend/
    └── index.html        Interfaz completa (HTML, CSS y JavaScript sin dependencias)
```

## Puesta en marcha

Requisito: Python 3.10 o superior.

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Abrir `http://localhost:8000`. La documentación interactiva de la API queda en `http://localhost:8000/docs`.

La primera ejecución crea `riesgos.db` y carga el proyecto **Portal de matrícula en línea (DEMO)**, que trae errores intencionales (riesgo sin dueño, riesgo sin tratamiento, exclusión sin justificar en la SoA, revisiones vencidas, residual sin aprobar) para analizarlos en clase. Para volver al estado inicial: borrar `riesgos.db` o llamar `POST /api/reiniciar-demo`.

Para usarlo en red local con el curso: `uvicorn app:app --host 0.0.0.0 --port 8000` y compartir la IP del equipo.

## Módulos de la interfaz

| Pestaña | Uso | AE |
|---|---|---|
| Asignatura | Competencia, aprendizajes esperados y mapa de contenidos | |
| Contenidos | Cada contenido con conceptos, aplicación, ejemplo, cláusulas, controles y preguntas | AE1, AE2, AE3 |
| ISO/IEC 27001 | Cláusulas 4 a 10, Anexo A filtrable (marca los 11 controles nuevos de 2022) y tabla matriz a norma | AE1 |
| Matriz de riesgos | Registro completo, sugerencia de controles por palabras clave, mapa de calor inherente, residual y actual | AE1, AE2 |
| Seguimiento | Registro de revisiones con desviaciones y acciones correctivas, gráfico de tendencia contra apetito y residual objetivo | AE3 |
| Declaración de aplicabilidad | 93 controles: aplicable, justificación, riesgos que lo requieren, estado de implementación | AE2 |
| Conciliación ISO 27001 | Verificación automática requisito por requisito con porcentaje de conformidad | AE2, AE3 |

Exportaciones CSV (separador `;`, compatibles con Excel): matriz, SoA y registro de revisiones.

## Reglas de conciliación

| Cláusula | Qué verifica |
|---|---|
| 6.1.2 a) | Apetito de riesgo definido en el proyecto |
| 6.1.2 c) 1 | Cada riesgo declara dimensión C, I o D |
| 6.1.2 c) 2 | Cada riesgo tiene dueño |
| 6.1.2 d) | Probabilidad e impacto evaluados |
| 6.1.2 e) | Priorización contra el apetito |
| 6.1.3 a) | Riesgos sobre el apetito con opción de tratamiento; aceptación con justificación |
| 6.1.3 b) c) | Riesgos a mitigar o transferir con controles del Anexo A |
| 6.1.3 d) | SoA sin pendientes, exclusiones justificadas, sin controles excluidos que un riesgo requiere |
| 6.1.3 e) | Plan de tratamiento escrito |
| 6.1.3 f) | Residual estimado y aprobado por el dueño; alerta si el residual aceptado supera el apetito |
| 8.2 | Fechas de revisión no vencidas |
| 8.3 | Controles aplicables implementados |
| 9.1 | Cada riesgo con al menos una revisión |
| 10.2 | Desviaciones con acción correctiva; alerta por desviaciones repetidas |
| A.5.8 | Control de seguridad en gestión de proyectos declarado aplicable |

## API principal

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/unidades` | Unidades y contenidos |
| GET | `/api/iso/clausulas` | Cláusulas 4 a 10 |
| GET | `/api/iso/controles?q=&tema=&solo_nuevos=` | Anexo A filtrado |
| GET | `/api/iso/controles/{id}` | Detalle, contenidos y riesgos que lo usan |
| GET | `/api/buscar?q=` | Búsqueda global |
| POST | `/api/sugerir-controles` | Sugerencia de controles a partir de un texto |
| GET/POST | `/api/proyectos` | Proyectos |
| GET/POST | `/api/proyectos/{id}/riesgos` | Matriz del proyecto |
| GET/PUT/DELETE | `/api/riesgos/{id}` | Riesgo |
| GET/POST | `/api/riesgos/{id}/revisiones` | Seguimiento |
| GET | `/api/proyectos/{id}/mapa-calor?tipo=inherente\|residual\|actual` | Mapa de calor |
| GET/PUT | `/api/proyectos/{id}/soa[/{control}]` | Declaración de aplicabilidad |
| GET | `/api/proyectos/{id}/conciliacion` | Conciliación con la norma |
| GET | `/api/proyectos/{id}/export/{matriz\|soa\|revisiones}.csv` | Exportaciones |

## Personalización

Todo el contenido académico está en `backend/contenido.json`: textos de cada contenido, escalas de probabilidad e impacto, rangos de nivel, categorías, cláusulas y palabras clave de cada control. Se edita sin tocar el código. Los nombres de los contenidos de la Unidad 2 deben ajustarse al programa oficial si difieren.

## Actividad sugerida

1. Analizar el proyecto DEMO en la pestaña Conciliación y corregir cada hallazgo "falta" justificando la cláusula.
2. Cada grupo crea su proyecto, define el apetito y la frecuencia de revisión (plan de gestión de riesgos).
3. Identificar al menos 10 riesgos con metalenguaje causa, evento y efecto, cubriendo 4 categorías.
4. Completar la SoA de los 93 controles.
5. Registrar dos ciclos de revisión con al menos una desviación y su acción correctiva.
6. Entregar los tres CSV y la captura de la conciliación con conformidad igual o superior a 85%.

## Nota sobre la norma

Las descripciones de cláusulas y controles son redacción propia con fines docentes. No reemplazan el texto oficial de ISO/IEC 27001:2022 ni la guía ISO/IEC 27002:2022, que deben consultarse en la versión adquirida por la institución.
