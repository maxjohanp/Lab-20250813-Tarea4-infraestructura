# Parche aplicado a Fortigate_CIS_check

Herramienta de terceros: https://github.com/priyam001/Fortigate_CIS_check (rama `main`).

## Problemas encontrados

El repositorio original quedó a medio actualizar. Una parte del código ya usa el modelo nuevo, con estados `PASS`, `FAIL` y `MANUAL_REVIEW`, y otra parte sigue con el anterior. Eso causó dos fallos al ejecutar `run_audit.py`:

1. **La carpeta de salida quedaba vacía.** `reporting/html_report.py` usa atributos que `scoring.py` nunca calcula:
   - `report.evaluated_rules`
   - `report.manual_review_rules`
   - `report.manual_review_results`
   - `report.level1` y `report.level2`
   - `report.severity`
   - `CategoryScore.manual_review`

   Por eso la generación del HTML terminaba con `AttributeError`.
2. **`AttributeError: 'bool' object has no attribute 'value'`.** Las reglas (`rules/level1_rules.py` y `rules/level2_rules.py`) siguen llamando a `_make_result(True/False, ...)`, pero `rules/base.py` espera un `RuleStatus`. Además del error en el HTML, ninguna regla contaba como aprobada.

## Corrección (3 archivos)

| Archivo | Cambio |
|---|---|
| `cis_benchmark/rules/base.py` | `_make_result` convierte `True`/`False` en `RuleStatus.PASS`/`RuleStatus.FAIL`. |
| `cis_benchmark/scoring.py` | Añade los atributos que faltaban sin quitar los anteriores. Los controles en revisión manual se excluyen del porcentaje, como indica el propio informe. |
| `run_audit.py` | El resumen de consola muestra también "Evaluated" y "Manual Review". El script de remediación incluye los controles de revisión manual. |

## Cómo aplicarlo

1. Copiar `base.py` en `Fortigate_CIS_check\cis_benchmark\rules\`.
2. Copiar `scoring.py` en `Fortigate_CIS_check\cis_benchmark\`.
3. Copiar `run_audit.py` en `Fortigate_CIS_check\`.
