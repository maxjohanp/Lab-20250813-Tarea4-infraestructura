#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening_0813.py
=====================
Auditoria y hardening automatizado basado en CIS Benchmarks para la red del
laboratorio 0813 (router Cisco 7200, switch Cisco IOSvL2 y firewall FortiGate).

Autor      : Maxyohan Montas Pena  (matricula 2025-0813)
Asignatura : Seguridad de Redes - ITLA
Benchmarks : CIS Cisco IOS 15 Benchmark v4.1.1
             CIS Fortigate 7.0.x Benchmark v1.3.0

MODOS
    python cis_hardening_0813.py auditar   -> crea un informe SIN aplicar ninguna regla
    python cis_hardening_0813.py aplicar   -> aplica las reglas y genera el informe postumo
    python cis_hardening_0813.py           -> muestra un menu para elegir

OPCIONES
    --equipos R-0813,FW-0813   limita los equipos (por defecto, todos)
    --offline CARPETA          audita archivos de configuracion guardados (solo auditar)
    --si                       no pide confirmacion antes de aplicar
    --debug                    guarda el dialogo SSH en la carpeta logs/

REQUISITOS
    Python 3.10 o superior y:   pip install "netmiko[par4]"
    (par4 = Paramiko 4.x; Paramiko 5 ya no habla los algoritmos SSH de IOS 15.2)

Las claves NO se guardan en este archivo: el script las pide al ejecutarse
(o las toma de las variables de entorno CIS_USER, CIS_PASS y CIS_ENABLE).
"""

import argparse
import datetime as dt
import getpass
import html
import os
import platform
import re
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ============================================================================
# 1. DATOS DEL LABORATORIO  (lo unico que hay que tocar si cambia la red)
# ============================================================================
ESTUDIANTE = "Maxyohan Montas Peña"
MATRICULA = "2025-0813"
ASIGNATURA = "Seguridad de Redes"

ADMIN_IP = "10.20.25.100"      # IP de la PC de administracion (Windows)
ACL_VTY = "113"                # ACL extendida que protege las lineas VTY
ZONA_HORARIA_FGT = "15"        # 15 = (GMT-4:00) La Paz -> misma hora que Santo Domingo
SERVICIOS_LAN = ["DNS", "HTTP", "HTTPS", "PING", "NTP"]   # reemplazan a "ALL"
AVISO = "ACCESO RESTRINGIDO: solo personal autorizado. Toda la actividad queda registrada."

EQUIPOS = [
    {"nombre": "R-0813", "tipo": "cisco_ios", "ip": "10.20.25.1",
     "rol": "Router Cisco 7200 (IOS 15.2)"},
    {"nombre": "SW-0813", "tipo": "cisco_ios", "ip": "10.20.25.2",
     "rol": "Switch Cisco IOSvL2 (IOS 15.2)"},
    {"nombre": "FW-0813", "tipo": "fortinet", "ip": "10.8.13.1",
     "rol": "Firewall FortiGate-VM 7.0.9", "wan": "port1"},
]

BENCHMARK = {
    "cisco_ios": "CIS Cisco IOS 15 Benchmark v4.1.1",
    "fortinet": "CIS Fortigate 7.0.x Benchmark v1.3.0",
}

RAIZ = Path(__file__).resolve().parent.parent      # carpeta del repositorio
DIR_INFORMES = RAIZ / "informes"
DIR_CONFIGS = RAIZ / "running-configs"
DIR_RESPALDOS = RAIZ / "respaldos"
DIR_LOGS = RAIZ / "logs"


# ============================================================================
# 2. UTILIDADES
# ============================================================================
def _preparar_consola():
    """Colores ANSI y UTF-8 en la consola de Windows."""
    if os.name == "nt":
        os.system("")
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m" if COLOR else texto


def verde(t): return c(t, "92")
def rojo(t): return c(t, "91")
def amarillo(t): return c(t, "93")
def azul(t): return c(t, "96")
def negrita(t): return c(t, "1")


@dataclass
class Control:
    """Resultado de evaluar una recomendacion CIS en un equipo."""
    id: str
    titulo: str
    nivel: str
    porque: str
    cumple: bool
    evidencia: str
    comandos: list = field(default_factory=list)   # remediacion automatica
    nota: str = ""                                 # remediacion manual u omision


@dataclass
class Resultado:
    """Todo lo que paso con un equipo durante la ejecucion."""
    equipo: dict
    conectado: bool = False
    error: str = ""
    antes: list = field(default_factory=list)
    despues: list = field(default_factory=list)
    aplicados: list = field(default_factory=list)   # [(id, [comandos], error)]
    archivo_config: str = ""


def porcentaje(controles):
    if not controles:
        return 0
    return round(100 * sum(1 for x in controles if x.cumple) / len(controles))


def ip_origen_hacia(ip_destino):
    """IP local con la que esta PC sale hacia un equipo (para no bloquearnos)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip_destino, 22))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def clave_cumple_politica(clave):
    return (len(clave) >= 8 and re.search(r"[a-z]", clave) and re.search(r"[A-Z]", clave)
            and re.search(r"\d", clave) and re.search(r"[^A-Za-z0-9]", clave))


# ============================================================================
# 3. CONTROLES CIS PARA CISCO IOS 15  (router y switch)
# ============================================================================
def _bloques_linea(cfg):
    """Devuelve {'line con 0': [sublineas], 'line vty 0 4': [...], ...}."""
    bloques, actual = {}, None
    for ln in cfg.splitlines():
        if ln.startswith("line "):
            actual = ln.strip()
            bloques[actual] = []
        elif actual and ln.startswith(" "):
            bloques[actual].append(ln.strip())
        else:
            actual = None
    return bloques


def _timeout(sub):
    """(cumple, texto) para exec-timeout: mayor que 0 y de 10 minutos o menos."""
    for s in sub:
        m = re.match(r"exec-timeout (\d+)(?: (\d+))?", s)
        if m:
            seg = int(m.group(1)) * 60 + int(m.group(2) or 0)
            return 0 < seg <= 600, f"exec-timeout {m.group(1)} {m.group(2) or 0}"
    return True, "valor por defecto (10 min)"


def controles_ios(cfg, ctx):
    """Evalua las recomendaciones elegidas del CIS Cisco IOS 15 Benchmark v4.1.1."""
    def hay(patron):
        return re.search(patron, cfg, re.M) is not None

    def linea(patron, si_no="(no está en la configuración)"):
        m = re.search(patron, cfg, re.M)
        return m.group(0).strip() if m else si_no

    lineas = _bloques_linea(cfg)
    vty = {n: s for n, s in lineas.items() if n.startswith("line vty")}
    con = lineas.get("line con 0", [])
    aux = lineas.get("line aux 0")
    admin_ok = ctx.get("origen") in ("", None, ADMIN_IP)   # "" = modo offline
    omitido = (f"OMITIDO: tu PC sale con la IP {ctx.get('origen')}, no con {ADMIN_IP}; "
               f"aplicar esta regla te dejaría fuera.")
    r = []

    def add(id_, titulo, nivel, porque, cumple, evidencia, comandos=None, nota=""):
        r.append(Control(id_, titulo, nivel, porque, bool(cumple), evidencia,
                         list(comandos or []), nota))

    # ---- 1. Plano de gestion ------------------------------------------------
    add("1.1.1", "Enable 'aaa new-model'", "L1",
        "Activa AAA: el control de acceso deja de depender de cada línea y se centraliza.",
        hay(r"^aaa new-model"), linea(r"^(no )?aaa new-model"), ["aaa new-model"])

    add("1.1.2", "Enable 'aaa authentication login'", "L1",
        "Obliga a autenticarse con usuario y clave (base local) en todos los accesos.",
        hay(r"^aaa authentication login \S+ \S+"), linea(r"^aaa authentication login.*"),
        ["aaa authentication login default local"])

    ok = bool(vty) and all([x for x in s if x.startswith("transport input")] ==
                           ["transport input ssh"] for s in vty.values())
    ev = "; ".join(f"{n}: " + (next((x for x in s if x.startswith("transport input")),
                                    "sin 'transport input'")) for n, s in vty.items())
    add("1.2.2", "Set 'transport input ssh' for 'line vty' connections", "L1",
        "Telnet envía usuario y clave en texto claro; SSH cifra toda la sesión.",
        ok, ev or "sin líneas vty",
        [x for n in vty for x in (n, "transport input ssh")])

    if aux is None:
        add("1.2.3", "Set 'no exec' for 'line aux 0'", "L1",
            "El puerto auxiliar no se usa; con 'no exec' nadie abre una sesión por ahí.",
            True, "el equipo no tiene línea aux")
    else:
        add("1.2.3", "Set 'no exec' for 'line aux 0'", "L1",
            "El puerto auxiliar no se usa; con 'no exec' nadie abre una sesión por ahí.",
            "no exec" in aux, "no exec" if "no exec" in aux else "line aux 0 permite sesiones (exec)",
            ["line aux 0", "no exec"])

    clases = {n: next((x.split()[1] for x in s if x.startswith("access-class ")
                       and x.endswith(" in")), "") for n, s in vty.items()}
    acl = next((v for v in clases.values() if v), ACL_VTY)
    cuerpo = "\n".join(re.findall(rf"^access-list {re.escape(acl)} .*$", cfg, re.M))
    m = re.search(rf"^ip access-list extended {re.escape(acl)}\n((?: .*\n?)+)", cfg, re.M)
    if m:
        cuerpo += "\n" + m.group(1)
    ok = bool(re.search(r"permit\s+tcp", cuerpo)) and bool(re.search(r"deny\s+ip any any", cuerpo))
    add("1.2.4", "Create 'access-list' for use with 'line vty'", "L1",
        "Define desde qué dirección se puede administrar el equipo y registra el resto.",
        ok, f"ACL {acl}: " + ("permit tcp + deny ip any any" if ok else "no existe o está incompleta"),
        [f"no access-list {ACL_VTY}",
         f"access-list {ACL_VTY} remark CIS 1.2.4 - SSH solo desde la PC de administracion",
         f"access-list {ACL_VTY} permit tcp host {ADMIN_IP} any",
         f"access-list {ACL_VTY} deny ip any any log"] if admin_ok else [],
        "" if admin_ok else omitido)

    ok = bool(vty) and all(clases.values())
    ev = "; ".join(f"{n}: " + (f"access-class {v} in" if v else "sin access-class")
                   for n, v in clases.items())
    add("1.2.5", "Set 'access-class' for 'line vty'", "L1",
        "Aplica la ACL a las líneas VTY: solo la PC de administración puede abrir SSH.",
        ok, ev or "sin líneas vty",
        [x for n in vty for x in (n, f"access-class {ACL_VTY} in")] if admin_ok else [],
        "" if admin_ok else omitido)

    ok, ev = _timeout(con)
    add("1.2.7", "Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'", "L1",
        "Una consola olvidada abierta queda disponible para cualquiera; se cierra sola.",
        ok, f"line con 0: {ev}", ["line con 0", "exec-timeout 5 0"])

    res = {n: _timeout(s) for n, s in vty.items()}
    add("1.2.9", "Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'", "L1",
        "Cierra las sesiones remotas inactivas para que no puedan ser reutilizadas.",
        all(v[0] for v in res.values()),
        "; ".join(f"{n}: {v[1]}" for n, v in res.items()) or "sin líneas vty",
        [x for n, v in res.items() if not v[0] for x in (n, "exec-timeout 5 0")])

    add("1.3.2", "Set the 'banner-text' for 'banner login'", "L1",
        "El aviso legal antes de iniciar sesión deja claro que el acceso está restringido.",
        hay(r"^banner login "), "banner login configurado" if hay(r"^banner login ") else "sin banner login",
        [f"banner login ^{AVISO}^"])

    add("1.3.3", "Set the 'banner-text' for 'banner motd'", "L1",
        "Mensaje del día con el aviso de uso autorizado para todo el que se conecte.",
        hay(r"^banner motd "), "banner motd configurado" if hay(r"^banner motd ") else "sin banner motd",
        [f"banner motd ^{AVISO}^"])

    add("1.4.1", "Set 'password' for 'enable secret'", "L1",
        "El modo privilegiado queda protegido con una clave guardada como hash.",
        hay(r"^enable secret "), "enable secret presente" if hay(r"^enable secret ") else "sin enable secret",
        nota="MANUAL: configure terminal -> enable secret <CLAVE>")

    add("1.4.2", "Enable 'service password-encryption'", "L1",
        "Evita que las claves de tipo 0 se lean a simple vista en la configuración.",
        hay(r"^service password-encryption"), linea(r"^(no )?service password-encryption"),
        ["service password-encryption"])

    usuarios = re.findall(r"^username (\S+) .*$", cfg, re.M)
    debiles = re.findall(r"^username (\S+) (?:(?!secret).)*password .*$", cfg, re.M)
    add("1.4.3", "Set 'username secret' for all local users", "L1",
        "Las claves de los usuarios locales se guardan como hash, no reversibles.",
        bool(usuarios) and not debiles,
        ("usuarios con secret: " + ", ".join(usuarios)) if usuarios and not debiles
        else ("usuarios con 'password': " + ", ".join(debiles) if debiles else "sin usuarios locales"),
        nota="MANUAL: configure terminal -> username <USUARIO> secret <CLAVE>")

    # ---- 2. Plano de control ------------------------------------------------
    m = re.search(r"^ip ssh time-out (\d+)", cfg, re.M)
    add("2.1.1.1.4", "Set 'seconds' for 'ip ssh timeout'", "L1",
        "Limita a 60 s el tiempo para autenticarse: menos ventana para ataques.",
        bool(m) and int(m.group(1)) <= 60,
        m.group(0) if m else "valor por defecto (120 s)", ["ip ssh time-out 60"])

    add("2.1.1.2", "Set version 2 for 'ip ssh version'", "L1",
        "SSH versión 1 tiene fallos conocidos; solo se acepta la versión 2.",
        hay(r"^ip ssh version 2"), linea(r"^ip ssh version \d", "sin 'ip ssh version' (acepta v1 y v2)"),
        ["ip ssh version 2"])

    for id_, patron, cmd, titulo, porque in [
        ("2.1.2", r"^no cdp run", "no cdp run", "Set 'no cdp run'",
         "CDP anuncia modelo, versión e IP a cualquier vecino: información para un atacante."),
        ("2.1.3", r"^no ip bootp server", "no ip bootp server", "Set 'no ip bootp server'",
         "El servidor BOOTP no se usa y es una puerta más expuesta."),
        ("2.1.4", r"^no service dhcp", "no service dhcp", "Set 'no service dhcp'",
         "Este equipo no reparte direcciones; el servicio DHCP sobra y se apaga."),
        ("2.1.6", r"^service tcp-keepalives-in", "service tcp-keepalives-in",
         "Set 'service tcp-keepalives-in'",
         "Detecta y cierra sesiones entrantes colgadas que ocupan líneas VTY."),
        ("2.1.7", r"^service tcp-keepalives-out", "service tcp-keepalives-out",
         "Set 'service tcp-keepalives-out'",
         "Detecta y cierra sesiones salientes colgadas."),
        ("2.1.8", r"^no service pad", "no service pad", "Set 'no service pad'",
         "PAD (X.25) es un servicio heredado que no se usa."),
        ("2.2.2", r"^logging buffered \d+", "logging buffered 64000",
         "Set 'buffer size' for 'logging buffered'",
         "Guarda los eventos en memoria para poder revisar qué pasó en el equipo."),
        ("2.2.3", r"^logging console critical", "logging console critical",
         "Set 'logging console critical'",
         "Solo los eventos críticos van a la consola: no la saturan ni frenan el equipo."),
        ("3.1.1", r"^no ip source-route", "no ip source-route", "Set 'no ip source-route'",
         "Impide que el emisor elija la ruta del paquete para saltarse los controles."),
    ]:
        add(id_, titulo, "L1", porque, hay(patron),
            cmd if hay(patron) else f"falta '{cmd}'", [cmd])

    return r


# ============================================================================
# 4. CONTROLES CIS PARA FORTIGATE 7.0.x
# ============================================================================
FGT_DEFECTOS = {   # valores de fabrica de FortiOS 7.0 (cuando la linea no aparece)
    "pre-login-banner": "disable", "post-login-banner": "disable", "timezone": "04",
    "admin-lockout-threshold": "3", "admin-lockout-duration": "60", "admintimeout": "5",
    "hostname": "",
}

FGT_SECCIONES = ["system global", "system interface", "system password-policy",
                 "system admin", "firewall policy"]


def parsear_fortigate(texto):
    """Convierte 'config ... / edit ... / set ...' en {seccion: {'_': {}, 'entradas': {}}}."""
    cfg, pila, sec, ent = {}, [], None, None
    lineas = texto.replace("\r", "").split("\n")
    i = 0
    while i < len(lineas):
        ln = lineas[i].strip()
        i += 1
        if not ln or ln.startswith("#"):
            continue
        # valores entre comillas que ocupan varias lineas (certificados, mensajes)
        while (ln.startswith("set ") and len(re.findall(r'(?<!\\)"', ln)) % 2 == 1
               and i < len(lineas)):
            ln += "\n" + lineas[i]
            i += 1
        if ln.startswith("config "):
            pila.append("config")
            if len(pila) == 1:
                sec = ln[7:].strip()
                cfg.setdefault(sec, {"_": {}, "entradas": {}})
                ent = None
        elif ln.startswith("edit "):
            pila.append("edit")
            if len(pila) == 2 and sec:
                ent = ln[5:].strip().strip('"')
                cfg[sec]["entradas"].setdefault(ent, {})
        elif ln == "next":
            if pila and pila[-1] == "edit":
                pila.pop()
            if len(pila) == 1:
                ent = None
        elif ln == "end":
            if pila:
                pila.pop()
            if not pila:
                sec = ent = None
        elif ln.startswith(("set ", "unset ")) and sec:
            partes = ln.split(None, 2)
            clave = partes[1]
            valor = partes[2].strip() if ln.startswith("set ") and len(partes) > 2 else ""
            if len(pila) == 1:
                cfg[sec]["_"][clave] = valor
            elif len(pila) == 2 and ent is not None:
                cfg[sec]["entradas"][ent][clave] = valor
    return cfg


def controles_fortigate(texto, ctx):
    """Evalua las recomendaciones elegidas del CIS Fortigate 7.0.x Benchmark v1.3.0."""
    cfg = parsear_fortigate(texto)
    for seccion in ("system global", "system interface"):
        if seccion not in cfg:
            raise ValueError(f"la configuración de FortiGate no trae 'config {seccion}'")
    glob = cfg.get("system global", {}).get("_", {})
    ifs = cfg.get("system interface", {}).get("entradas", {})
    pol = cfg.get("system password-policy", {}).get("_", {})
    admins = cfg.get("system admin", {}).get("entradas", {})
    reglas = cfg.get("firewall policy", {}).get("entradas", {})
    wan = ctx.get("wan", "port1")
    admin_ok = ctx.get("origen") in ("", None, ADMIN_IP)

    def g(clave):
        return glob.get(clave, FGT_DEFECTOS.get(clave, "")).strip('"')

    def acceso(nombre):
        return ifs.get(nombre, {}).get("allowaccess", "").split()

    r = []

    def add(id_, titulo, nivel, porque, cumple, evidencia, comandos=None, nota=""):
        r.append(Control(id_, titulo, nivel, porque, bool(cumple), evidencia,
                         list(comandos or []), nota))

    def en_global(*sets):
        return ["config system global", *sets, "end"]

    # ---- 1. Red ---------------------------------------------------------------
    serv = acceso(wan)
    add("1.3", "Disable all management related services on WAN port", "L1",
        "La interfaz que da a Internet no debe ofrecer HTTPS, HTTP, SSH ni ping: "
        "es donde llegan los ataques.",
        wan in ifs and not serv,
        f"{wan} allowaccess: " + (" ".join(serv) if serv else "(vacío)") if wan in ifs
        else f"no existe la interfaz {wan} (revisa 'wan' en EQUIPOS)",
        ["config system interface", f"edit {wan}", "unset allowaccess", "next", "end"]
        if wan in ifs else [])

    # ---- 2. Sistema -------------------------------------------------------------
    add("2.1.1", "Ensure 'Pre-Login Banner' is set", "L1",
        "Muestra el aviso legal antes de pedir credenciales.",
        g("pre-login-banner") == "enable", f"pre-login-banner {g('pre-login-banner')}",
        en_global("set pre-login-banner enable"))

    add("2.1.2", "Ensure 'Post-Login-Banner' is set", "L1",
        "El administrador debe aceptar el aviso de uso al entrar.",
        g("post-login-banner") == "enable", f"post-login-banner {g('post-login-banner')}",
        en_global("set post-login-banner enable"))

    add("2.1.3", "Ensure timezone is properly configured", "L1",
        "Los registros deben tener la hora local correcta para poder investigar un incidente.",
        g("timezone").lstrip("0") == ZONA_HORARIA_FGT.lstrip("0"),
        f"timezone {g('timezone')} (esperado {ZONA_HORARIA_FGT})",
        en_global(f"set timezone {ZONA_HORARIA_FGT}"))

    nombre = g("hostname")
    add("2.1.5", "Ensure hostname is set", "L1",
        "Un nombre propio identifica al equipo en registros, alertas y respaldos.",
        bool(nombre) and not nombre.lower().startswith("fortigate"),
        f"hostname {nombre or '(de fábrica)'}",
        nota="MANUAL: config system global -> set hostname FW-0813 -> end")

    def n(clave):
        try:
            return int(pol.get(clave, "0"))
        except ValueError:
            return 0
    ok = (pol.get("status") == "enable" and n("minimum-length") >= 8
          and all(n(k) >= 1 for k in ("min-lower-case-letter", "min-upper-case-letter",
                                      "min-non-alphanumeric", "min-number")))
    clave_ok = ctx.get("clave") is None or clave_cumple_politica(ctx["clave"])
    add("2.2.1", "Ensure 'Password Policy' is enabled", "L1",
        "Exige claves largas y complejas a los administradores: resisten fuerza bruta.",
        ok, f"password-policy status {pol.get('status', 'disable')}, "
            f"minimum-length {pol.get('minimum-length', '8')}",
        ["config system password-policy", "set status enable",
         "set apply-to admin-password ipsec-preshared-key", "set minimum-length 8",
         "set min-lower-case-letter 1", "set min-upper-case-letter 1",
         "set min-non-alphanumeric 1", "set min-number 1", "set expire-status enable",
         "set expire-day 90", "set reuse-password disable", "end"] if clave_ok else [],
        "" if clave_ok else "OMITIDO: la clave de admin no cumple la política (8+, mayúscula, "
                             "minúscula, número y símbolo). Cámbiala y repite.")

    try:
        umbral, bloqueo = int(g("admin-lockout-threshold")), int(g("admin-lockout-duration"))
    except ValueError:
        umbral, bloqueo = 99, 0
    add("2.2.2", "Ensure administrator password retries and lockout time are configured", "L1",
        "Tras 3 intentos fallidos bloquea el origen 15 minutos: frena la fuerza bruta.",
        umbral <= 3 and bloqueo >= 900,
        f"admin-lockout-threshold {umbral}, admin-lockout-duration {bloqueo}",
        en_global("set admin-lockout-threshold 3", "set admin-lockout-duration 900"))

    sin = [a for a, d in admins.items()
           if not any(v and v != "0.0.0.0 0.0.0.0" for k, v in d.items()
                      if re.fullmatch(r"trusthost\d+", k))]
    add("2.4.2", "Ensure all the login accounts having specific trusted hosts enabled", "L1",
        "Aunque alguien robe la clave, solo se puede iniciar sesión desde la PC de administración.",
        bool(admins) and not sin,
        ("sin trusted hosts: " + ", ".join(sin)) if sin or not admins
        else "todas las cuentas tienen trusted hosts",
        (["config system admin"]
         + [x for a in sin for x in (f'edit "{a}"',
                                     f"set trusthost1 {ADMIN_IP} 255.255.255.255", "next")]
         + ["end"]) if admin_ok else [],
        "" if admin_ok else f"OMITIDO: tu PC sale con la IP {ctx.get('origen')}, no con {ADMIN_IP}; "
                            f"aplicar esta regla te dejaría fuera.")

    try:
        inactividad = int(g("admintimeout"))
    except ValueError:
        inactividad = 999
    add("2.4.4", "Ensure idle timeout time is configured", "L1",
        "Cierra la sesión de administración tras 5 minutos sin actividad.",
        0 < inactividad <= 5, f"admintimeout {inactividad}", en_global("set admintimeout 5"))

    malos = {i: s for i in ifs for s in [acceso(i)] if "http" in s or "telnet" in s}
    arreglo = []
    for i, s in malos.items():
        resto = [x for x in s if x not in ("http", "telnet")]
        arreglo += [f"edit {i}",
                    "unset allowaccess" if i == wan or not resto
                    else "set allowaccess " + " ".join(resto), "next"]
    add("2.4.5", "Ensure only encrypted access channels are enabled", "L1",
        "HTTP y Telnet mandan la clave en texto claro; solo quedan HTTPS y SSH.",
        not malos,
        "; ".join(f"{i}: {' '.join(s)}" for i, s in malos.items()) or "ninguna interfaz usa http ni telnet",
        ["config system interface", *arreglo, "end"])

    # ---- 3. Politicas -------------------------------------------------------------
    activas = {i: d for i, d in reglas.items() if d.get("status", "enable") != "disable"}
    con_all = [i for i, d in activas.items()
               if "ALL" in [t.strip('"') for t in d.get("service", "").split()]]
    add("3.2", "Ensure that policies do not use \"ALL\" as Service", "L1",
        "Cada regla debe decir qué servicios permite; 'ALL' deja pasar cualquier puerto.",
        not con_all,
        ("políticas con ALL: " + ", ".join(con_all)) if con_all
        else ("no hay políticas activas" if not activas else "ninguna política usa ALL"),
        ["config firewall policy"]
        + [x for i in con_all for x in (f"edit {i}", "set service "
                                        + " ".join(f'"{s}"' for s in SERVICIOS_LAN), "next")]
        + ["end"])

    sin_log = [i for i, d in activas.items() if d.get("logtraffic", "utm") != "all"]
    add("3.4", "Ensure logging is enabled on all firewall policies", "L1",
        "Sin registro de todas las sesiones no hay forma de reconstruir un incidente.",
        not sin_log,
        ("políticas sin 'logtraffic all': " + ", ".join(sin_log)) if sin_log
        else ("no hay políticas activas" if not activas else "todas registran todas las sesiones"),
        ["config firewall policy"]
        + [x for i in sin_log for x in (f"edit {i}", "set logtraffic all", "next")] + ["end"])
    return r


# ============================================================================
# 5. CONEXION, LECTURA Y APLICACION
# ============================================================================
def limpiar_secretos(texto):
    """Quita hashes y llaves antes de guardar una configuracion en el repositorio."""
    t = re.sub(r"(\b(?:secret|password) \d+ )\S+", r"\1<ELIMINADO>", texto)
    t = re.sub(r"(\bkey-string (?:\d+ )?)\S+", r"\1<ELIMINADO>", t)
    t = re.sub(r"(snmp-server community )\S+", r"\1<ELIMINADO>", t)
    t = re.sub(r"\bENC \S+", "ENC <ELIMINADO>", t)
    t = re.sub(r'(set private-key )"[^"]*"', r'\1"<ELIMINADO>"', t, flags=re.S)
    return t


def conectar(eq, cred, debug):
    from netmiko import ConnectHandler
    datos = dict(device_type=eq["tipo"], host=eq["ip"], username=cred["usuario"],
                 password=cred["clave"], conn_timeout=25, auth_timeout=25,
                 banner_timeout=25, fast_cli=False)
    if eq["tipo"] == "cisco_ios":
        datos["secret"] = cred["enable"]
    if debug:
        DIR_LOGS.mkdir(exist_ok=True)
        datos["session_log"] = str(DIR_LOGS / f"{eq['nombre']}_sesion.log")
    con = ConnectHandler(**datos)
    if eq["tipo"] == "cisco_ios" and not con.check_enable_mode():
        con.enable()
    return con


def leer_config(con, eq):
    """Texto de configuracion sobre el que se evaluan los controles."""
    if eq["tipo"] == "cisco_ios":
        return con.send_command("show running-config", read_timeout=180)
    partes = []
    for s in FGT_SECCIONES:
        salida = con.send_command(f"show full-configuration {s}", read_timeout=120)
        if f"config {s}" not in salida:
            raise RuntimeError(f"FortiGate no devolvió la sección '{s}': "
                               + " ".join(salida.split())[:120])
        partes.append(salida)
    return "\n".join(partes)


def evaluar(eq, texto, origen, clave=None):
    ctx = {"origen": origen, "wan": eq.get("wan", "port1"), "clave": clave}
    return controles_ios(texto, ctx) if eq["tipo"] == "cisco_ios" else controles_fortigate(texto, ctx)


def guardar_ios(con):
    """write memory. El c7200 de GNS3 puede preguntar 'Overwrite the previous NVRAM
    configuration?[confirm]' (NVRAM escrita por otra version); si aparece, se confirma
    con Enter en lugar de quedarse esperando el prompt hasta agotar el tiempo."""
    prompt = re.escape(con.base_prompt) + r"#"
    salida = con.send_command("write memory", expect_string=rf"\[confirm\]|{prompt}",
                              read_timeout=120, strip_prompt=False, strip_command=False)
    if "[confirm]" in salida:
        con.write_channel(con.RETURN)
        salida += con.read_until_pattern(pattern=prompt, read_timeout=120)
    return salida


def aplicar(con, eq, controles):
    """Envia la remediacion de cada control que no cumple. Devuelve [(id, cmds, error)]."""
    hechos = []
    pendientes = [x for x in controles if not x.cumple and x.comandos]
    if not pendientes:
        return hechos
    if eq["tipo"] == "cisco_ios":
        con.config_mode()
        for x in pendientes:
            salida = con.send_config_set(x.comandos, enter_config_mode=False,
                                         exit_config_mode=False, read_timeout=60)
            errores = [l.strip() for l in salida.splitlines() if l.strip().startswith("%")]
            hechos.append((x.id, x.comandos, "; ".join(errores)))
        con.exit_config_mode()
        guardar_ios(con)
    else:
        for x in pendientes:
            errores = []
            for cmd in x.comandos:
                salida = con.send_command(cmd, expect_string=r"[#$]\s*$", read_timeout=60,
                                          strip_prompt=False, strip_command=False)
                if re.search(r"(?i)command fail|parse error|unknown action|not found", salida):
                    errores.append(f"{cmd} -> " + " ".join(salida.split())[:120])
            hechos.append((x.id, x.comandos, "; ".join(errores)))
    return hechos


def guardar_config(con, eq, texto, carpeta, sufijo="running-config", completa=True):
    """Guarda la configuracion sin secretos. FortiGate: 'show full-configuration'."""
    carpeta.mkdir(parents=True, exist_ok=True)
    ext = "txt" if eq["tipo"] == "cisco_ios" else "conf"
    if eq["tipo"] == "fortinet" and completa:
        try:
            texto = con.send_command("show full-configuration", read_timeout=900)
        except Exception:                                     # noqa: BLE001
            print(amarillo("      (la configuración completa tardó demasiado; se guarda 'show')"))
            con.clear_buffer()
            texto = con.send_command("show", read_timeout=600)
    ruta = carpeta / f"{eq['nombre']}_{sufijo}.{ext}"
    ruta.write_text(limpiar_secretos(texto).strip() + "\n", encoding="utf-8")
    return ruta


def procesar(eq, modo, cred, debug, sello):
    """Flujo completo sobre un equipo real."""
    res = Resultado(equipo=eq)
    try:
        con = conectar(eq, cred, debug)
    except Exception as e:                                    # noqa: BLE001
        res.error = f"{type(e).__name__}: {' '.join(str(e).split())[:300]}"
        return res
    res.conectado = True
    try:
        origen = ip_origen_hacia(eq["ip"])
        texto = leer_config(con, eq)
        res.antes = evaluar(eq, texto, origen, cred["clave"])
        mostrar_tabla(res.antes)
        if modo == "aplicar":
            guardar_config(con, eq, texto, DIR_RESPALDOS / sello, "antes", completa=False)
            pendientes = [x for x in res.antes if not x.cumple and x.comandos]
            print(f"      Aplicando {len(pendientes)} recomendaciones...", flush=True)
            res.aplicados = aplicar(con, eq, res.antes)
            for id_, _, err in res.aplicados:
                print("        " + (amarillo(f"{id_}: revisar -> {err}") if err else verde(f"{id_}: aplicado")))
            texto = leer_config(con, eq)
            res.despues = evaluar(eq, texto, origen, cred["clave"])
            print(negrita("      Verificación después de aplicar:"))
            mostrar_tabla(res.despues, antes=res.antes)
        print("      Guardando running-config...", flush=True)
        res.archivo_config = str(guardar_config(con, eq, texto, DIR_CONFIGS))
    except Exception as e:                                    # noqa: BLE001
        res.error = f"{type(e).__name__}: {' '.join(str(e).split())[:300]}"
    finally:
        try:
            con.disconnect()
        except Exception:
            pass
    return res


def procesar_offline(eq, carpeta):
    res = Resultado(equipo=eq)
    archivos = sorted(Path(carpeta).glob(f"{eq['nombre']}*"))
    if not archivos:
        res.error = f"no hay un archivo {eq['nombre']}* en {carpeta}"
        return res
    res.conectado = True
    res.archivo_config = str(archivos[0])
    texto = archivos[0].read_text(encoding="utf-8", errors="replace")
    res.antes = evaluar(eq, texto, "")
    mostrar_tabla(res.antes)
    return res


# ============================================================================
# 6. SALIDA EN PANTALLA E INFORMES
# ============================================================================
def mostrar_tabla(controles, antes=None):
    previos = {x.id: x.cumple for x in (antes or [])}
    print(f"      {'ID':<10} {'Recomendación CIS':<74} Estado")
    print("      " + "-" * 100)
    for x in controles:
        estado = verde("CUMPLE") if x.cumple else rojo("NO CUMPLE")
        if antes and x.cumple and previos.get(x.id) is False:
            estado = verde("CUMPLE") + azul("  <- corregido")
        print(f"      {x.id:<10} {x.titulo[:74]:<74} {estado}")
        if not x.cumple:
            print(f"      {'':<10} " + amarillo(f"evidencia: {x.evidencia}"[:100]))
            if x.nota:
                print(f"      {'':<10} " + amarillo(x.nota[:130]))
    ok = sum(1 for x in controles if x.cumple)
    print("      " + "-" * 100)
    print(negrita(f"      Resultado: {ok} de {len(controles)} cumplen ({porcentaje(controles)} %)"))


CSS = """
body{font-family:Segoe UI,Calibri,Arial,sans-serif;margin:0;background:#f1f5f9;color:#1f2937}
header{background:#0b1f3a;color:#fff;padding:28px 40px;border-bottom:6px solid #f59e0b}
header h1{margin:0 0 6px;font-size:26px} header p{margin:2px 0;color:#cbd5e1;font-size:14px}
main{max-width:1180px;margin:0 auto;padding:24px 40px 60px}
.tarjetas{display:flex;gap:16px;flex-wrap:wrap;margin:8px 0 26px}
.tarjeta{flex:1;min-width:230px;background:#fff;border-radius:12px;padding:16px 18px;
 border-left:6px solid #0f3d91;box-shadow:0 1px 3px rgba(15,23,42,.12)}
.tarjeta h3{margin:0;font-size:17px;color:#0b1f3a} .tarjeta small{color:#64748b}
.num{font-size:30px;font-weight:700;margin-top:8px}
.barra{height:10px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin-top:8px}
.barra i{display:block;height:100%;background:#047857}
h2{color:#0b1f3a;border-bottom:3px solid #f59e0b;padding-bottom:6px;margin-top:34px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13.5px;
 box-shadow:0 1px 3px rgba(15,23,42,.12)}
th{background:#0b1f3a;color:#fff;text-align:left;padding:9px 10px}
td{padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
tr:nth-child(even) td{background:#f8fafc}
.ok{color:#047857;font-weight:700;white-space:nowrap} .no{color:#dc2626;font-weight:700;white-space:nowrap}
.fix{background:#dbeafe;color:#1d4ed8;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:700}
code{font-family:Consolas,monospace;font-size:12.5px;color:#0f3d91;white-space:pre-wrap}
.err{background:#fef2f2;border-left:6px solid #dc2626;padding:12px 16px;border-radius:8px}
footer{color:#64748b;font-size:12.5px;margin-top:30px}
"""


def _estado_html(cumple):
    return '<span class="ok">CUMPLE</span>' if cumple else '<span class="no">NO CUMPLE</span>'


def informe_html(resultados, modo, cuando, offline):
    e = html.escape
    postumo = modo == "aplicar"
    titulo = "Informe póstumo de hardening CIS" if postumo else "Informe de auditoría CIS"
    p = [f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'><title>{titulo} · 0813</title>"
         f"<style>{CSS}</style></head><body><header><h1>{titulo}</h1>"
         f"<p>{e(ESTUDIANTE)} · matrícula {MATRICULA} · {ASIGNATURA}</p>"
         f"<p>Generado el {cuando:%d/%m/%Y a las %H:%M:%S} desde {e(platform.node())} · "
         f"modo <b>{modo.upper()}</b>{' (sin conexión, sobre archivos)' if offline else ''}</p>"
         f"</header><main><div class='tarjetas'>"]
    for r in resultados:
        eq = r.equipo
        if not r.conectado:
            p.append(f"<div class='tarjeta' style='border-color:#dc2626'><h3>{e(eq['nombre'])}</h3>"
                     f"<small>{e(eq['rol'])}</small><div class='num no'>sin conexión</div></div>")
            continue
        a = porcentaje(r.antes)
        sin_verificar = postumo and not r.despues     # fallo antes de la verificacion final
        d = porcentaje(r.despues) if (postumo and not sin_verificar) else a
        if not postumo:
            num = f"{a} %"
        else:
            num = f"{a} % &rarr; ?" if sin_verificar else f"{a} % &rarr; {d} %"
        pie = ("no se pudo verificar después de aplicar (ver el problema más abajo)" if sin_verificar
               else f"{sum(x.cumple for x in (r.despues if postumo else r.antes))} de "
                    f"{len(r.antes)} recomendaciones cumplen")
        borde = " style='border-color:#dc2626'" if sin_verificar else ""
        p.append(f"<div class='tarjeta'{borde}><h3>{e(eq['nombre'])}</h3><small>{e(eq['rol'])} · {eq['ip']}</small>"
                 f"<div class='num'>{num}</div><div class='barra'><i style='width:{d}%'></i></div>"
                 f"<small>{pie}</small></div>")
    p.append("</div>")
    for r in resultados:
        eq = r.equipo
        p.append(f"<h2>{e(eq['nombre'])} · {e(BENCHMARK[eq['tipo']])}</h2>")
        if r.error:
            p.append(f"<div class='err'><b>Problema:</b> {e(r.error)}</div>")
        if not r.antes:
            continue
        desp = {x.id: x for x in r.despues}
        hechos = {i: (cmds, err) for i, cmds, err in r.aplicados}
        cab = ("<th>Antes</th><th>Después</th><th>Evidencia final</th><th>Comandos aplicados</th>"
               if postumo else "<th>Estado</th><th>Evidencia</th><th>Remediación propuesta</th>")
        p.append(f"<table><tr><th>ID</th><th>Recomendación CIS</th><th>Nivel</th>{cab}</tr>")
        for x in r.antes:
            fila = f"<tr><td><b>{x.id}</b></td><td>{e(x.titulo)}<br><small>{e(x.porque)}</small></td><td>{x.nivel}</td>"
            if postumo and x.id not in desp:          # sin verificacion final
                cmds, err = hechos.get(x.id, ([], ""))
                fila += (f"<td>{_estado_html(x.cumple)}</td><td>&mdash;</td>"
                         f"<td>{e(x.evidencia)}</td><td><code>{e(chr(10).join(cmds))}</code></td>")
            elif postumo:
                y = desp[x.id]
                marca = " <span class='fix'>corregido</span>" if (y.cumple and not x.cumple) else ""
                cmds, err = hechos.get(x.id, ([], ""))
                extra = f"<br><small class='no'>{e(err)}</small>" if err else ""
                nota = f"<small>{e(y.nota)}</small>" if (not y.cumple and y.nota) else ""
                fila += (f"<td>{_estado_html(x.cumple)}</td><td>{_estado_html(y.cumple)}{marca}</td>"
                         f"<td>{e(y.evidencia)}</td><td><code>{e(chr(10).join(cmds))}</code>{extra}{nota}</td>")
            else:
                rem = (f"<code>{e(chr(10).join(x.comandos))}</code>" if x.comandos
                       else f"<small>{e(x.nota)}</small>") if not x.cumple else ""
                fila += f"<td>{_estado_html(x.cumple)}</td><td>{e(x.evidencia)}</td><td>{rem}</td>"
            p.append(fila + "</tr>")
        p.append("</table>")
        if r.archivo_config:
            p.append(f"<p><small>Configuración: {e(Path(r.archivo_config).name)}</small></p>")
    p.append("<footer>Script: scripts/cis_hardening_0813.py · Benchmarks: CIS Cisco IOS 15 v4.1.1 y "
             "CIS Fortigate 7.0.x v1.3.0 · Las claves y hashes no se incluyen en los archivos."
             "</footer></main></body></html>")
    return "\n".join(p)


def informe_md(resultados, modo, cuando, offline):
    postumo = modo == "aplicar"
    t = [f"# {'Informe póstumo de hardening CIS' if postumo else 'Informe de auditoría CIS'}", "",
         f"- **Estudiante:** {ESTUDIANTE} · matrícula {MATRICULA} · {ASIGNATURA}",
         f"- **Fecha y hora:** {cuando:%d/%m/%Y %H:%M:%S} · PC: {platform.node()}",
         f"- **Modo:** {modo.upper()}{' (sin conexión)' if offline else ''}", "",
         "## Resumen", ""]
    t += (["| Equipo | Benchmark | Antes | Después |", "|---|---|---|---|"] if postumo
          else ["| Equipo | Benchmark | Cumplimiento |", "|---|---|---|"])
    for r in resultados:
        eq = r.equipo
        if not r.antes:
            t.append(f"| {eq['nombre']} | {BENCHMARK[eq['tipo']]} | sin conexión |" + (" |" if postumo else ""))
        elif postumo:
            desp_txt = f"{porcentaje(r.despues)} %" if r.despues else "sin verificar (ver problema)"
            t.append(f"| {eq['nombre']} | {BENCHMARK[eq['tipo']]} | {porcentaje(r.antes)} % | {desp_txt} |")
        else:
            t.append(f"| {eq['nombre']} | {BENCHMARK[eq['tipo']]} | {porcentaje(r.antes)} % "
                     f"({sum(x.cumple for x in r.antes)} de {len(r.antes)}) |")
    si = {True: "✅ Cumple", False: "❌ No cumple"}
    for r in resultados:
        eq = r.equipo
        t += ["", f"## {eq['nombre']} · {eq['rol']} ({eq['ip']})", ""]
        if r.error:
            t += [f"> **Problema:** {r.error}", ""]
        if not r.antes:
            continue
        desp = {x.id: x for x in r.despues}
        hechos = {i: cmds for i, cmds, _ in r.aplicados}
        t += (["| ID | Recomendación CIS | Antes | Después | Comandos aplicados |", "|---|---|---|---|---|"]
              if postumo else ["| ID | Recomendación CIS | Estado | Evidencia |", "|---|---|---|---|"])
        for x in r.antes:
            tit = x.titulo.replace("|", "\\|")
            if postumo:
                y = desp.get(x.id)
                cmds = "<br>".join(f"`{c_}`" for c_ in hechos.get(x.id, []))
                t.append(f"| {x.id} | {tit} | {si[x.cumple]} | {si[y.cumple] if y else '—'} | {cmds} |")
            else:
                t.append(f"| {x.id} | {tit} | {si[x.cumple]} | {x.evidencia.replace('|', '/')} |")
    return "\n".join(t) + "\n"


# ============================================================================
# 7. PROGRAMA PRINCIPAL
# ============================================================================
def pedir_credenciales():
    usuario = os.environ.get("CIS_USER") or input("  Usuario SSH [admin]: ").strip() or "admin"
    clave = os.environ.get("CIS_PASS") or getpass.getpass("  Clave SSH (no se muestra): ")
    enable = os.environ.get("CIS_ENABLE")
    if enable is None:
        enable = getpass.getpass("  Enable secret de Cisco (Enter = la misma clave): ") or clave
    return {"usuario": usuario, "clave": clave, "enable": enable}


def menu():
    print("  ¿Qué quieres hacer?")
    print("    1) AUDITAR  - crear un informe sin aplicar ninguna regla")
    print("    2) APLICAR  - aplicar las reglas y generar el informe póstumo")
    print("    3) Salir")
    op = input("  Opción [1]: ").strip() or "1"
    return {"1": "auditar", "2": "aplicar"}.get(op)


def main():
    _preparar_consola()
    ap = argparse.ArgumentParser(description="Auditoría y hardening CIS del laboratorio 0813")
    ap.add_argument("modo", nargs="?", choices=["auditar", "aplicar"])
    ap.add_argument("--equipos", help="lista separada por comas, p. ej. R-0813,FW-0813")
    ap.add_argument("--offline", metavar="CARPETA", help="audita archivos guardados")
    ap.add_argument("--si", action="store_true", help="no pedir confirmación al aplicar")
    ap.add_argument("--debug", action="store_true", help="guardar el diálogo SSH en logs/")
    a = ap.parse_args()

    cuando = dt.datetime.now()
    sello = f"{cuando:%Y%m%d-%H%M}"
    print(negrita("=" * 106))
    print(negrita("  CIS HARDENING 0813 · auditoría y hardening automatizado (CIS Benchmarks)"))
    print(f"  {ESTUDIANTE} · matrícula {MATRICULA} · {ASIGNATURA}")
    print(f"  Fecha y hora: {cuando:%d/%m/%Y %H:%M:%S} · PC: {platform.node()}")
    print(negrita("=" * 106))

    modo = a.modo or menu()
    if not modo:
        return 0
    if a.offline and modo == "aplicar":
        print(rojo("  --offline solo sirve para auditar."))
        return 2
    equipos = EQUIPOS
    if a.equipos:
        pedidos = {x.strip().upper() for x in a.equipos.split(",")}
        equipos = [e_ for e_ in EQUIPOS if e_["nombre"].upper() in pedidos]
        if not equipos:
            print(rojo("  Ningún equipo coincide con --equipos."))
            return 2

    cred = None
    if not a.offline:
        try:
            import netmiko                                   # noqa: F401
            import paramiko
        except ImportError:
            print(rojo('  Falta Netmiko. Instálalo con:  pip install "netmiko[par4]"'))
            return 2
        if int(paramiko.__version__.split(".")[0]) >= 5:
            print(amarillo('  AVISO: tienes Paramiko 5. IOS 15.2 usa algoritmos SSH antiguos; '
                           'si el router o el switch no conectan ejecuta:  pip install "netmiko[par4]"'))
        cred = pedir_credenciales()
        if modo == "aplicar" and not a.si:
            print(amarillo(f"\n  Modo APLICAR: se va a cambiar la configuración de "
                           f"{', '.join(e_['nombre'] for e_ in equipos)}."))
            if input("  ¿Continuar? (s/N): ").strip().lower() not in ("s", "si", "sí"):
                print("  Cancelado. No se cambió nada.")
                return 0

    resultados = []
    for i, eq in enumerate(equipos, 1):
        print()
        print(negrita(f"[{i}/{len(equipos)}] {eq['nombre']} ({eq['ip']}) · {eq['rol']}"))
        print(f"      {BENCHMARK[eq['tipo']]}")
        if a.offline:
            res = procesar_offline(eq, a.offline)
        else:
            print("      Conectando por SSH...", flush=True)
            res = procesar(eq, modo, cred, a.debug, sello)
        if res.error:
            print(rojo(f"      PROBLEMA: {res.error}"))
        resultados.append(res)

    DIR_INFORMES.mkdir(exist_ok=True)
    base = DIR_INFORMES / f"{'informe_postumo' if modo == 'aplicar' else 'informe_auditoria'}_{sello}"
    base.with_suffix(".html").write_text(informe_html(resultados, modo, cuando, bool(a.offline)), encoding="utf-8")
    base.with_suffix(".md").write_text(informe_md(resultados, modo, cuando, bool(a.offline)), encoding="utf-8")

    print()
    print(negrita("=" * 106))
    print(negrita("  RESUMEN"))
    for r in resultados:
        if not r.antes:
            print(f"    {r.equipo['nombre']:<9} " + rojo("sin datos (revisa la conexión)"))
        elif modo == "aplicar" and not r.despues:
            print(f"    {r.equipo['nombre']:<9} {porcentaje(r.antes):>3} %  ->  "
                  + rojo("sin verificar (ver PROBLEMA arriba)"))
        elif modo == "aplicar":
            print(f"    {r.equipo['nombre']:<9} {porcentaje(r.antes):>3} %  ->  "
                  + verde(f"{porcentaje(r.despues)} %") + f"   ({len(r.aplicados)} recomendaciones aplicadas)")
        else:
            print(f"    {r.equipo['nombre']:<9} {porcentaje(r.antes):>3} %   "
                  f"({sum(x.cumple for x in r.antes)} de {len(r.antes)} cumplen)")
    print(f"  Informe HTML : {base.with_suffix('.html')}")
    print(f"  Informe MD   : {base.with_suffix('.md')}")
    if not a.offline:
        print(f"  Configs      : {DIR_CONFIGS}")
    print(negrita("=" * 106))
    return 0 if all(r.antes for r in resultados) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  Interrumpido por el usuario.")
        sys.exit(130)
