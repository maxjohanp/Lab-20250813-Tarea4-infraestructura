# Parche aplicado a ONYX (CAAAT)

Herramienta de terceros: https://github.com/UncleSocks/onyx-caaat-automated-cisco-ios-configuration-assessment-and-auditing-tool

## Problema encontrado

La auditoría del "antes" funcionó, pero la del "después" se detenía con este error:

```
TypeError: 'builtin_function_or_method' object is not subscriptable
```

El fallo está en `parser_modules/ios15/line_parsers.py`, en la función `compliance_check_vty_ac`. Ese código usa `match.group['ac']` y `match.group['dir']` con corchetes, cuando `group` es un método y se llama con paréntesis.

Esa parte solo se ejecuta cuando las líneas VTY ya tienen un `access-class`. Por eso el error apareció recién después de aplicar las recomendaciones CIS 1.2.4 y 1.2.5.

## Corrección

En `line_parsers.py`, líneas 64 y 65:

```python
access_class = config_regex_pattern_search.group('ac')
direction = config_regex_pattern_search.group('dir')
```

## Cómo aplicarlo

Copiar `line_parsers.py` en `onyx\src\onyx_unclesocks\parser_modules\ios15\`.
