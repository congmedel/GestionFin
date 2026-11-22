"""
Gestión de Riesgos ISI604 | Backend
Matriz de riesgos de proyectos informáticos conciliada con ISO/IEC 27001:2022.

Ejecutar:
    pip install -r requirements.txt
    uvicorn app:app --reload --port 8000
Luego abrir http://localhost:8000
Documentación interactiva de la API: http://localhost:8000/docs
"""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import unicodedata
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
FRONTEND = BASE.parent / "frontend"
DB_PATH = BASE / "riesgos.db"
CONTENIDO = json.loads((BASE / "contenido.json").read_text(encoding="utf-8"))
CONTROLES = {c["id"]: c for c in CONTENIDO["controles"]}
CLAUSULAS = {c["id"]: c for c in CONTENIDO["clausulas"]}
ESC = CONTENIDO["escalas"]

app = FastAPI(title="Gestión de Riesgos ISI604 · ISO/IEC 27001:2022", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ----------------------------------------------------------------- utilidades
def normalizar(t: str) -> str:
    t = unicodedata.normalize("NFD", (t or "").lower())
    return "".join(ch for ch in t if unicodedata.category(ch) != "Mn")


def nivel(p: Optional[int], i: Optional[int]) -> dict:
    if not p or not i:
        return {"valor": None, "nombre": "Sin evaluar"}
    v = p * i
    for n in ESC["niveles"]:
        if n["min"] <= v <= n["max"]:
            return {"valor": v, "nombre": n["nombre"]}
    return {"valor": v, "nombre": "Crítico"}


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


ESQUEMA = """
CREATE TABLE IF NOT EXISTS proyectos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    descripcion TEXT DEFAULT '',
    equipo TEXT DEFAULT '',
    apetito INTEGER NOT NULL DEFAULT 9,
    frecuencia_revision_dias INTEGER NOT NULL DEFAULT 14,
    creado TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS riesgos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    codigo TEXT NOT NULL,
    titulo TEXT NOT NULL,
    fase TEXT DEFAULT '',
    categoria TEXT DEFAULT '',
    incertidumbre TEXT DEFAULT '',
    activo TEXT DEFAULT '',
    amenaza TEXT DEFAULT '',
    vulnerabilidad TEXT DEFAULT '',
    cid TEXT DEFAULT '',
    dueno TEXT DEFAULT '',
    probabilidad INTEGER,
    impacto INTEGER,
    controles_existentes TEXT DEFAULT '',
    tratamiento TEXT DEFAULT '',
    plan_tratamiento TEXT DEFAULT '',
    controles TEXT DEFAULT '[]',
    prob_residual INTEGER,
    impacto_residual INTEGER,
    aprobado_dueno INTEGER DEFAULT 0,
    estado TEXT DEFAULT 'Abierto',
    fecha_identificacion TEXT,
    proxima_revision TEXT
);
CREATE TABLE IF NOT EXISTS revisiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    riesgo_id INTEGER NOT NULL REFERENCES riesgos(id) ON DELETE CASCADE,
    fecha TEXT NOT NULL,
    revisor TEXT DEFAULT '',
    probabilidad INTEGER,
    impacto INTEGER,
    estado TEXT DEFAULT '',
    desviacion_tipo TEXT DEFAULT 'Ninguna',
    desviacion_detalle TEXT DEFAULT '',
    accion TEXT DEFAULT '',
    comentario TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS soa (
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    aplicable INTEGER,
    justificacion TEXT DEFAULT '',
    estado_implementacion TEXT DEFAULT 'No iniciado',
    PRIMARY KEY (proyecto_id, control_id)
);
"""


def fila_riesgo(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["controles"] = json.loads(d.get("controles") or "[]")
    d["aprobado_dueno"] = bool(d["aprobado_dueno"])
    d["nivel_inherente"] = nivel(d["probabilidad"], d["impacto"])
    d["nivel_residual"] = nivel(d["prob_residual"], d["impacto_residual"])
    return d


# ------------------------------------------------------------- datos de demo
def sembrar_demo(con: sqlite3.Connection) -> None:
    hoy = date.today()
    cur = con.execute(
        "INSERT INTO proyectos (nombre, descripcion, equipo, apetito, frecuencia_revision_dias, creado) VALUES (?,?,?,?,?,?)",
        (
            "Portal de matrícula en línea (DEMO)",
            "Desarrollo de un portal web para postulación y matrícula de estudiantes, integrado con el sistema académico legado y con pagos en línea. Despliegue en nube pública.",
            "Patrocinador: Dirección Académica | Jefe de proyecto: C. Rojas | Coordinador de riesgos: M. Pérez | Jefe de desarrollo: A. Soto | Jefe de infraestructura: L. Díaz",
            9, 14, hoy.isoformat(),
        ),
    )
    pid = cur.lastrowid
    R = [
        ("R-01", "Saturación del servicio de autenticación en periodo de matrícula", "Pruebas", "Técnico",
         "Se asume que el servicio institucional soporta 5.000 usuarios simultáneos; no existen pruebas de carga.",
         "Servicio de autenticación institucional", "Demanda masiva concurrente", "Capacidad no dimensionada ni probada",
         "D", "L. Díaz (Jefe de infraestructura)", 4, 4, "Monitoreo básico de CPU", "Mitigar",
         "Pruebas de carga con 2x la demanda esperada; escalamiento horizontal automático; ventana de matrícula escalonada por carrera.",
         ["8.6", "8.14", "5.30"], 2, 3, 1, "En tratamiento", -20, 4),
        ("R-02", "Explotación de vulnerabilidades conocidas en componentes del framework", "Desarrollo", "Técnico",
         "Se desconoce el nivel de mantenimiento de algunas librerías de terceros.",
         "Servidor de aplicaciones y dependencias", "Atacante externo", "Librerías desactualizadas sin gestión de parches",
         "C,I,D", "A. Soto (Jefe de desarrollo)", 3, 4, "Ninguno", "Mitigar",
         "Análisis de dependencias en cada build (SCA), parchado en máximo 15 días para críticas.",
         ["8.8", "5.21", "8.25"], 2, 4, 1, "Monitoreo", -25, -2),
        ("R-03", "Inyección SQL en formulario de postulación", "Desarrollo", "Técnico",
         "No se ha definido un estándar de codificación segura para el equipo.",
         "Base de datos de postulantes", "Atacante externo", "Consultas construidas por concatenación",
         "C,I", "A. Soto (Jefe de desarrollo)", 4, 5, "Revisión de código informal", "Mitigar",
         "Consultas parametrizadas, ORM, pruebas DAST antes de cada pase a producción.",
         ["8.28", "8.29", "8.26", "5.34"], 2, 5, 1, "En tratamiento", -18, 10),
        ("R-04", "Retraso en integración con el sistema académico legado", "Análisis y diseño", "Gestión del proyecto",
         "La documentación de la API del sistema legado está incompleta y su proveedor responde con demora.",
         "Cronograma del proyecto", "Dependencia de proveedor", "Documentación técnica incompleta",
         "D", "C. Rojas (Jefe de proyecto)", 4, 3, "Reuniones semanales con el proveedor", "Mitigar",
         "Acuerdo de nivel de servicio de soporte con el proveedor; desarrollo de un simulador (mock) de la API.",
         ["5.19", "5.20", "5.22"], None, None, 0, "Abierto", -15, -3),
        ("R-05", "Pérdida de datos de matrícula por falla del almacenamiento", "Despliegue", "Técnico",
         "No está definido el RPO aceptable para la Dirección Académica.",
         "Base de datos de matrícula", "Falla de hardware o error humano", "Sin respaldo automatizado ni pruebas de restauración",
         "I,D", "L. Díaz (Jefe de infraestructura)", 3, 5, "Snapshot manual semanal", "Mitigar",
         "Respaldo diario cifrado fuera del sitio, prueba de restauración mensual.",
         ["8.13", "8.24"], 1, 5, 1, "Monitoreo", -30, 6),
        ("R-06", "Uso de datos reales de postulantes en ambiente de pruebas", "Pruebas", "Legal / regulatorio",
         "",
         "Datos personales de postulantes", "Personal interno o proveedor", "Copia directa de producción a QA",
         "C", "", 3, 4, "Ninguno", "",
         "", [], None, None, 0, "Abierto", -10, -1),
        ("R-07", "Rotación del desarrollador líder antes del despliegue", "Desarrollo", "Personas",
         "El conocimiento del módulo de pagos está concentrado en una sola persona.",
         "Conocimiento del equipo", "Renuncia o licencia", "Falta de documentación y de respaldo de roles",
         "D", "C. Rojas (Jefe de proyecto)", 2, 3, "Ninguno", "Aceptar",
         "Se acepta y se monitorea; se documentará el módulo de pagos en la wiki.",
         ["5.37"], 2, 3, 1, "Monitoreo", -12, 2),
        ("R-08", "Bucket de almacenamiento en la nube expuesto públicamente", "Despliegue", "Externo / proveedores",
         "El equipo no tiene experiencia previa en la configuración del proveedor de nube.",
         "Documentos adjuntos de postulantes", "Atacante externo que escanea buckets públicos", "Configuración por defecto sin revisión",
         "C", "L. Díaz (Jefe de infraestructura)", 3, 5, "Ninguno", "Mitigar",
         "Plantilla de infraestructura como código con bloqueo de acceso público y revisión de configuración.",
         ["5.23", "8.9", "6.3"], None, None, 0, "Abierto", -8, 6),
    ]
    ids = {}
    for (cod, tit, fase, cat, inc, act, ame, vul, cid, dueno, p, i, ce, trat, plan, ctrls, pr, ir, apr, est, dident, drev) in R:
        c = con.execute(
            """INSERT INTO riesgos (proyecto_id,codigo,titulo,fase,categoria,incertidumbre,activo,amenaza,vulnerabilidad,cid,dueno,
            probabilidad,impacto,controles_existentes,tratamiento,plan_tratamiento,controles,prob_residual,impacto_residual,
            aprobado_dueno,estado,fecha_identificacion,proxima_revision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, cod, tit, fase, cat, inc, act, ame, vul, cid, dueno, p, i, ce, trat, plan, json.dumps(ctrls), pr, ir, apr, est,
             (hoy + timedelta(days=dident)).isoformat(), (hoy + timedelta(days=drev)).isoformat()),
        )
        ids[cod] = c.lastrowid
    revs = [
        ("R-01", -10, "M. Pérez", 4, 4, "En tratamiento", "Ninguna", "", "", "Pruebas de carga planificadas para semana 8."),
        ("R-02", -16, "M. Pérez", 3, 4, "En tratamiento", "Seguridad de la información", "Escaneo detecta 3 dependencias con CVE críticos.", "Actualización inmediata de dependencias.", ""),
        ("R-02", -2, "M. Pérez", 2, 4, "Monitoreo", "Ninguna", "", "", "SCA integrado al pipeline; 0 críticas abiertas."),
        ("R-04", -9, "C. Rojas", 4, 3, "Abierto", "Plazo", "SPI = 0,88 en el hito de integración.", "Escalar al patrocinador; solicitar soporte prioritario.", ""),
        ("R-04", -3, "C. Rojas", 5, 3, "Abierto", "Plazo", "SPI = 0,82; la API entrega respuestas inconsistentes.", "Construir simulador de la API.", "La desviación se repite: reevaluar tratamiento."),
        ("R-05", -14, "L. Díaz", 2, 5, "En tratamiento", "Ninguna", "", "", "Respaldo diario operativo."),
        ("R-05", -1, "L. Díaz", 1, 5, "Monitoreo", "Ninguna", "", "", "Prueba de restauración exitosa en 40 minutos."),
    ]
    for cod, d, rev, p, i, est, dt, dd, acc, com in revs:
        con.execute(
            "INSERT INTO revisiones (riesgo_id,fecha,revisor,probabilidad,impacto,estado,desviacion_tipo,desviacion_detalle,accion,comentario) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ids[cod], (hoy + timedelta(days=d)).isoformat(), rev, p, i, est, dt, dd, acc, com),
        )
    soa = [
        ("5.8", 1, "Todo proyecto del portafolio debe integrar la seguridad de la información en su gestión.", "En implementación"), ("8.6", 1, "", "En implementación"), ("8.14", 1, "", "No iniciado"),
        ("8.8", 1, "", "Implementado"), ("5.21", 1, "", "Implementado"), ("8.28", 1, "", "En implementación"),
        ("8.13", 1, "", "Implementado"), ("8.24", 1, "", "Implementado"),
        ("7.1", 0, "El proyecto se despliega en nube pública; la seguridad física del centro de datos es responsabilidad del proveedor (ver 5.23).", "No aplica"),
        ("7.12", 0, "", "No aplica"),
    ]
    for cid_, apl, just, est in soa:
        con.execute("INSERT INTO soa VALUES (?,?,?,?,?)", (pid, cid_, apl, just, est))


def iniciar() -> None:
    with db() as con:
        con.executescript(ESQUEMA)
        if con.execute("SELECT COUNT(*) FROM proyectos").fetchone()[0] == 0:
            sembrar_demo(con)


iniciar()


# ------------------------------------------------------------------ modelos
class ProyectoIn(BaseModel):
    nombre: str
    descripcion: str = ""
    equipo: str = ""
    apetito: int = Field(9, ge=1, le=25)
    frecuencia_revision_dias: int = Field(14, ge=1, le=180)


class RiesgoIn(BaseModel):
    codigo: Optional[str] = None
    titulo: str
    fase: str = ""
    categoria: str = ""
    incertidumbre: str = ""
    activo: str = ""
    amenaza: str = ""
    vulnerabilidad: str = ""
    cid: str = ""
    dueno: str = ""
    probabilidad: Optional[int] = Field(None, ge=1, le=5)
    impacto: Optional[int] = Field(None, ge=1, le=5)
    controles_existentes: str = ""
    tratamiento: str = ""
    plan_tratamiento: str = ""
    controles: List[str] = []
    prob_residual: Optional[int] = Field(None, ge=1, le=5)
    impacto_residual: Optional[int] = Field(None, ge=1, le=5)
    aprobado_dueno: bool = False
    estado: str = "Abierto"
    fecha_identificacion: Optional[str] = None
    proxima_revision: Optional[str] = None


class RevisionIn(BaseModel):
    fecha: Optional[str] = None
    revisor: str = ""
    probabilidad: int = Field(..., ge=1, le=5)
    impacto: int = Field(..., ge=1, le=5)
    estado: str = ""
    desviacion_tipo: str = "Ninguna"
    desviacion_detalle: str = ""
    accion: str = ""
    comentario: str = ""


class SoaIn(BaseModel):
    aplicable: Optional[bool] = None
    justificacion: str = ""
    estado_implementacion: str = "No iniciado"


class TextoIn(BaseModel):
    texto: str


# ------------------------------------------------------ contenido académico
@app.get("/api/asignatura")
def asignatura():
    return CONTENIDO["asignatura"]


@app.get("/api/unidades")
def unidades():
    return CONTENIDO["unidades"]


@app.get("/api/escalas")
def escalas():
    return ESC


@app.get("/api/iso/clausulas")
def clausulas():
    return CONTENIDO["clausulas"]


@app.get("/api/iso/temas")
def temas():
    return CONTENIDO["temas"]


@app.get("/api/iso/controles")
def controles(q: str = "", tema: str = "", solo_nuevos: bool = False):
    nq = normalizar(q)
    out = []
    for c in CONTENIDO["controles"]:
        if tema and not c["id"].startswith(tema + "."):
            continue
        if solo_nuevos and not c.get("nuevo2022"):
            continue
        if nq:
            blob = normalizar(" ".join([c["id"], c["titulo"], c["descripcion"], " ".join(c["claves"])]))
            if nq not in blob:
                continue
        out.append(c)
    return out


@app.get("/api/iso/controles/{cid}")
def control(cid: str):
    if cid not in CONTROLES:
        raise HTTPException(404, "Control no existe en el Anexo A")
    c = dict(CONTROLES[cid])
    c["contenidos_relacionados"] = [
        {"id": k["id"], "titulo": k["titulo"]}
        for u in CONTENIDO["unidades"] for k in u["contenidos"] if cid in k.get("controles", [])
    ]
    with db() as con:
        rs = con.execute(
            "SELECT r.id, r.codigo, r.titulo, p.nombre AS proyecto FROM riesgos r JOIN proyectos p ON p.id=r.proyecto_id WHERE r.controles LIKE ?",
            (f'%"{cid}"%',),
        ).fetchall()
    c["riesgos"] = [dict(x) for x in rs]
    return c


@app.post("/api/sugerir-controles")
def sugerir(body: TextoIn):
    """Sugiere controles del Anexo A por coincidencia de palabras clave con la descripción del riesgo."""
    t = normalizar(body.texto)
    res = []
    for c in CONTENIDO["controles"]:
        hits = [k for k in c["claves"] if re.search(r"(?<![a-z0-9])" + re.escape(normalizar(k)) + r"(?:es|s)?(?![a-z0-9])", t)]
        if hits:
            res.append({"id": c["id"], "titulo": c["titulo"], "coincidencias": hits, "puntaje": len(hits)})
    res.sort(key=lambda x: (-x["puntaje"], [int(n) for n in x["id"].split(".")]))
    return res[:10]


@app.get("/api/buscar")
def buscar(q: str):
    nq = normalizar(q)
    if len(nq) < 2:
        return []
    res = []
    for u in CONTENIDO["unidades"]:
        for k in u["contenidos"]:
            blob = normalizar(json.dumps(k, ensure_ascii=False))
            if nq in blob:
                res.append({"tipo": "Contenido", "id": k["id"], "titulo": k["titulo"], "detalle": u["nombre"]})
    for c in CONTENIDO["clausulas"]:
        if nq in normalizar(json.dumps(c, ensure_ascii=False)):
            res.append({"tipo": "Cláusula", "id": c["id"], "titulo": c["titulo"], "detalle": c["grupo"]})
    for c in CONTENIDO["controles"]:
        if nq in normalizar(" ".join([c["id"], c["titulo"], c["descripcion"], " ".join(c["claves"])])):
            res.append({"tipo": "Control Anexo A", "id": c["id"], "titulo": c["titulo"], "detalle": c["descripcion"]})
    return res[:40]


# -------------------------------------------------------------- proyectos
@app.get("/api/proyectos")
def listar_proyectos():
    with db() as con:
        rows = con.execute(
            "SELECT p.*, (SELECT COUNT(*) FROM riesgos r WHERE r.proyecto_id=p.id) AS n_riesgos FROM proyectos p ORDER BY p.id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/proyectos", status_code=201)
def crear_proyecto(p: ProyectoIn):
    with db() as con:
        cur = con.execute(
            "INSERT INTO proyectos (nombre,descripcion,equipo,apetito,frecuencia_revision_dias,creado) VALUES (?,?,?,?,?,?)",
            (p.nombre, p.descripcion, p.equipo, p.apetito, p.frecuencia_revision_dias, date.today().isoformat()),
        )
        return {"id": cur.lastrowid}


@app.put("/api/proyectos/{pid}")
def editar_proyecto(pid: int, p: ProyectoIn):
    with db() as con:
        n = con.execute(
            "UPDATE proyectos SET nombre=?,descripcion=?,equipo=?,apetito=?,frecuencia_revision_dias=? WHERE id=?",
            (p.nombre, p.descripcion, p.equipo, p.apetito, p.frecuencia_revision_dias, pid),
        ).rowcount
    if not n:
        raise HTTPException(404, "Proyecto no encontrado")
    return {"ok": True}


@app.delete("/api/proyectos/{pid}")
def borrar_proyecto(pid: int):
    with db() as con:
        con.execute("DELETE FROM proyectos WHERE id=?", (pid,))
    return {"ok": True}


def obtener_proyecto(con, pid: int) -> dict:
    r = con.execute("SELECT * FROM proyectos WHERE id=?", (pid,)).fetchone()
    if not r:
        raise HTTPException(404, "Proyecto no encontrado")
    return dict(r)


# ---------------------------------------------------------------- riesgos
@app.get("/api/proyectos/{pid}/riesgos")
def listar_riesgos(pid: int):
    with db() as con:
        obtener_proyecto(con, pid)
        rows = con.execute("SELECT * FROM riesgos WHERE proyecto_id=? ORDER BY codigo", (pid,)).fetchall()
        out = []
        for r in rows:
            d = fila_riesgo(r)
            ult = con.execute("SELECT * FROM revisiones WHERE riesgo_id=? ORDER BY fecha DESC, id DESC LIMIT 1", (r["id"],)).fetchone()
            d["ultima_revision"] = dict(ult) if ult else None
            d["nivel_actual"] = nivel(ult["probabilidad"], ult["impacto"]) if ult else d["nivel_inherente"]
            out.append(d)
    return out


def validar_controles(ids: List[str]) -> List[str]:
    malos = [c for c in ids if c not in CONTROLES]
    if malos:
        raise HTTPException(422, f"Controles inexistentes en el Anexo A: {', '.join(malos)}")
    return sorted(set(ids), key=lambda x: [int(n) for n in x.split(".")])


@app.post("/api/proyectos/{pid}/riesgos", status_code=201)
def crear_riesgo(pid: int, r: RiesgoIn):
    ctrls = validar_controles(r.controles)
    with db() as con:
        p = obtener_proyecto(con, pid)
        codigo = r.codigo
        if not codigo:
            n = con.execute("SELECT COUNT(*) FROM riesgos WHERE proyecto_id=?", (pid,)).fetchone()[0] + 1
            codigo = f"R-{n:02d}"
        hoy = date.today()
        cur = con.execute(
            """INSERT INTO riesgos (proyecto_id,codigo,titulo,fase,categoria,incertidumbre,activo,amenaza,vulnerabilidad,cid,dueno,
            probabilidad,impacto,controles_existentes,tratamiento,plan_tratamiento,controles,prob_residual,impacto_residual,
            aprobado_dueno,estado,fecha_identificacion,proxima_revision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, codigo, r.titulo, r.fase, r.categoria, r.incertidumbre, r.activo, r.amenaza, r.vulnerabilidad, r.cid, r.dueno,
             r.probabilidad, r.impacto, r.controles_existentes, r.tratamiento, r.plan_tratamiento, json.dumps(ctrls),
             r.prob_residual, r.impacto_residual, int(r.aprobado_dueno), r.estado,
             r.fecha_identificacion or hoy.isoformat(),
             r.proxima_revision or (hoy + timedelta(days=p["frecuencia_revision_dias"])).isoformat()),
        )
        return {"id": cur.lastrowid, "codigo": codigo}


@app.get("/api/riesgos/{rid}")
def ver_riesgo(rid: int):
    with db() as con:
        r = con.execute("SELECT * FROM riesgos WHERE id=?", (rid,)).fetchone()
        if not r:
            raise HTTPException(404, "Riesgo no encontrado")
        d = fila_riesgo(r)
        d["revisiones"] = [dict(x) for x in con.execute(
            "SELECT * FROM revisiones WHERE riesgo_id=? ORDER BY fecha, id", (rid,)).fetchall()]
    d["controles_detalle"] = [CONTROLES[c] for c in d["controles"] if c in CONTROLES]
    return d


@app.put("/api/riesgos/{rid}")
def editar_riesgo(rid: int, r: RiesgoIn):
    ctrls = validar_controles(r.controles)
    with db() as con:
        n = con.execute(
            """UPDATE riesgos SET codigo=COALESCE(?,codigo),titulo=?,fase=?,categoria=?,incertidumbre=?,activo=?,amenaza=?,
            vulnerabilidad=?,cid=?,dueno=?,probabilidad=?,impacto=?,controles_existentes=?,tratamiento=?,plan_tratamiento=?,
            controles=?,prob_residual=?,impacto_residual=?,aprobado_dueno=?,estado=?,
            fecha_identificacion=COALESCE(?,fecha_identificacion),proxima_revision=COALESCE(?,proxima_revision) WHERE id=?""",
            (r.codigo, r.titulo, r.fase, r.categoria, r.incertidumbre, r.activo, r.amenaza, r.vulnerabilidad, r.cid, r.dueno,
             r.probabilidad, r.impacto, r.controles_existentes, r.tratamiento, r.plan_tratamiento, json.dumps(ctrls),
             r.prob_residual, r.impacto_residual, int(r.aprobado_dueno), r.estado, r.fecha_identificacion, r.proxima_revision, rid),
        ).rowcount
    if not n:
        raise HTTPException(404, "Riesgo no encontrado")
    return {"ok": True}


@app.delete("/api/riesgos/{rid}")
def borrar_riesgo(rid: int):
    with db() as con:
        con.execute("DELETE FROM riesgos WHERE id=?", (rid,))
    return {"ok": True}


# ------------------------------------------------------------- seguimiento
@app.get("/api/riesgos/{rid}/revisiones")
def listar_revisiones(rid: int):
    with db() as con:
        rows = con.execute("SELECT * FROM revisiones WHERE riesgo_id=? ORDER BY fecha, id", (rid,)).fetchall()
    return [dict(x) | {"nivel": nivel(x["probabilidad"], x["impacto"])} for x in rows]


@app.post("/api/riesgos/{rid}/revisiones", status_code=201)
def crear_revision(rid: int, v: RevisionIn):
    with db() as con:
        r = con.execute("SELECT r.*, p.frecuencia_revision_dias AS f FROM riesgos r JOIN proyectos p ON p.id=r.proyecto_id WHERE r.id=?", (rid,)).fetchone()
        if not r:
            raise HTTPException(404, "Riesgo no encontrado")
        fecha = v.fecha or date.today().isoformat()
        con.execute(
            "INSERT INTO revisiones (riesgo_id,fecha,revisor,probabilidad,impacto,estado,desviacion_tipo,desviacion_detalle,accion,comentario) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rid, fecha, v.revisor, v.probabilidad, v.impacto, v.estado or r["estado"], v.desviacion_tipo, v.desviacion_detalle, v.accion, v.comentario),
        )
        prox = (date.fromisoformat(fecha) + timedelta(days=r["f"])).isoformat()
        con.execute("UPDATE riesgos SET estado=?, proxima_revision=? WHERE id=?", (v.estado or r["estado"], prox, rid))
    return {"ok": True, "proxima_revision": prox}


@app.delete("/api/revisiones/{vid}")
def borrar_revision(vid: int):
    with db() as con:
        con.execute("DELETE FROM revisiones WHERE id=?", (vid,))
    return {"ok": True}


# -------------------------------------------------------------- mapa de calor
@app.get("/api/proyectos/{pid}/mapa-calor")
def mapa_calor(pid: int, tipo: str = "inherente"):
    riesgos = listar_riesgos(pid)
    celdas = {f"{p}-{i}": [] for p in range(1, 6) for i in range(1, 6)}
    for r in riesgos:
        if tipo == "residual":
            p, i = r["prob_residual"], r["impacto_residual"]
        elif tipo == "actual" and r["ultima_revision"]:
            p, i = r["ultima_revision"]["probabilidad"], r["ultima_revision"]["impacto"]
        else:
            p, i = r["probabilidad"], r["impacto"]
        if p and i:
            celdas[f"{p}-{i}"].append(r["codigo"])
    return {"tipo": tipo, "celdas": celdas}


# ------------------------------------------------- declaración de aplicabilidad
def construir_soa(con, pid: int) -> List[dict]:
    riesgos = [fila_riesgo(r) for r in con.execute("SELECT * FROM riesgos WHERE proyecto_id=?", (pid,)).fetchall()]
    over = {r["control_id"]: dict(r) for r in con.execute("SELECT * FROM soa WHERE proyecto_id=?", (pid,)).fetchall()}
    out = []
    for c in CONTENIDO["controles"]:
        usados = [r["codigo"] for r in riesgos if c["id"] in r["controles"]]
        o = over.get(c["id"])
        if o and o["aplicable"] is not None:
            aplicable = bool(o["aplicable"])
            origen = "Decisión registrada"
        elif usados:
            aplicable = True
            origen = "Seleccionado por la evaluación de riesgos"
        else:
            aplicable = None
            origen = "Pendiente de decisión"
        justif = (o or {}).get("justificacion") or ""
        if aplicable and not justif and usados:
            justif = "Tratamiento de " + ", ".join(usados)
        out.append({
            "id": c["id"], "titulo": c["titulo"], "tema": c["id"].split(".")[0],
            "aplicable": aplicable, "origen": origen, "riesgos": usados,
            "justificacion": justif,
            "justificacion_registrada": (o or {}).get("justificacion") or "",
            "estado_implementacion": (o or {}).get("estado_implementacion") or ("No iniciado" if aplicable else ""),
            "nuevo2022": bool(c.get("nuevo2022")),
        })
    return out


@app.get("/api/proyectos/{pid}/soa")
def soa(pid: int):
    with db() as con:
        obtener_proyecto(con, pid)
        return construir_soa(con, pid)


@app.put("/api/proyectos/{pid}/soa/{cid}")
def editar_soa(pid: int, cid: str, s: SoaIn):
    if cid not in CONTROLES:
        raise HTTPException(404, "Control no existe")
    with db() as con:
        obtener_proyecto(con, pid)
        con.execute(
            """INSERT INTO soa (proyecto_id,control_id,aplicable,justificacion,estado_implementacion) VALUES (?,?,?,?,?)
            ON CONFLICT(proyecto_id,control_id) DO UPDATE SET aplicable=excluded.aplicable,
            justificacion=excluded.justificacion, estado_implementacion=excluded.estado_implementacion""",
            (pid, cid, None if s.aplicable is None else int(s.aplicable), s.justificacion, s.estado_implementacion),
        )
    return {"ok": True}


# ------------------------------------------------- conciliación ISO 27001
def check(clausula, requisito, estado, detalle, items=None):
    return {"clausula": clausula, "requisito": requisito, "estado": estado, "detalle": detalle, "items": items or []}


@app.get("/api/proyectos/{pid}/conciliacion")
def conciliacion(pid: int):
    """Contrasta la matriz del proyecto con los requisitos de las cláusulas 6.1.2, 6.1.3, 8.2, 8.3, 9.1 y 10.2."""
    with db() as con:
        p = obtener_proyecto(con, pid)
        sa = construir_soa(con, pid)
    rs = listar_riesgos(pid)
    ap = p["apetito"]
    hoy = date.today().isoformat()
    C = []

    C.append(check("6.1.2 a)", "Criterios de aceptación y de evaluación definidos", "cumple" if ap else "falta",
                   f"Apetito de riesgo del proyecto: nivel {ap}. Escala 5x5 con criterios descritos para probabilidad e impacto."))

    if not rs:
        C.append(check("6.1.2 c)", "Riesgos identificados", "falta", "El proyecto aún no tiene riesgos registrados."))
    sin_cid = [r["codigo"] for r in rs if not r["cid"].strip()]
    C.append(check("6.1.2 c) 1", "Riesgos asociados a la pérdida de confidencialidad, integridad o disponibilidad",
                   "cumple" if rs and not sin_cid else ("alerta" if sin_cid else "falta"),
                   "Todos los riesgos indican la dimensión CID afectada." if not sin_cid else "Riesgos sin dimensión CID declarada.", sin_cid))

    sin_dueno = [r["codigo"] for r in rs if not r["dueno"].strip()]
    C.append(check("6.1.2 c) 2", "Dueño del riesgo identificado", "cumple" if not sin_dueno else "falta",
                   "Cada riesgo tiene un dueño con autoridad." if not sin_dueno else "Riesgos sin dueño asignado.", sin_dueno))

    sin_eval = [r["codigo"] for r in rs if not (r["probabilidad"] and r["impacto"])]
    C.append(check("6.1.2 d)", "Análisis de probabilidad, consecuencias y nivel", "cumple" if not sin_eval else "falta",
                   "Todos los riesgos tienen probabilidad e impacto." if not sin_eval else "Riesgos sin analizar.", sin_eval))

    sobre = [r for r in rs if (r["nivel_inherente"]["valor"] or 0) > ap]
    C.append(check("6.1.2 e)", "Evaluación contra criterios y priorización", "cumple",
                   f"{len(sobre)} de {len(rs)} riesgos superan el apetito ({ap}) y requieren tratamiento.",
                   [f'{r["codigo"]} ({r["nivel_inherente"]["valor"]})' for r in sorted(sobre, key=lambda x: -x["nivel_inherente"]["valor"])]))

    sin_trat = [r["codigo"] for r in sobre if not r["tratamiento"]]
    acept_sin_just = [r["codigo"] for r in sobre if r["tratamiento"] == "Aceptar" and not r["plan_tratamiento"].strip()]
    C.append(check("6.1.3 a)", "Opción de tratamiento seleccionada para los riesgos sobre el apetito",
                   "cumple" if not sin_trat and not acept_sin_just else "falta",
                   "Todos los riesgos sobre el apetito tienen opción de tratamiento." if not sin_trat and not acept_sin_just
                   else "Riesgos sobre el apetito sin tratamiento o aceptados sin justificación.", sin_trat + acept_sin_just))

    sin_ctrl = [r["codigo"] for r in rs if r["tratamiento"] in ("Mitigar", "Transferir") and not r["controles"]]
    C.append(check("6.1.3 b) c)", "Controles determinados y comparados con el Anexo A", "cumple" if not sin_ctrl else "falta",
                   "Los riesgos a mitigar o transferir tienen controles del Anexo A asignados." if not sin_ctrl
                   else "Riesgos a mitigar o transferir sin controles asignados.", sin_ctrl))

    pend = [s["id"] for s in sa if s["aplicable"] is None]
    excl_sin = [s["id"] for s in sa if s["aplicable"] is False and not s["justificacion_registrada"].strip()]
    incons = [f'{s["id"]} (usado en {", ".join(s["riesgos"])})' for s in sa if s["aplicable"] is False and s["riesgos"]]
    est = "cumple" if not pend and not excl_sin and not incons else ("falta" if excl_sin or incons else "alerta")
    det = f"{sum(1 for s in sa if s['aplicable'])} controles aplicables, {sum(1 for s in sa if s['aplicable'] is False)} excluidos, {len(pend)} pendientes de decisión."
    items = ([f"Exclusión sin justificar: {x}" for x in excl_sin] + [f"Excluido pero usado: {x}" for x in incons] +
             ([f"Pendientes: {', '.join(pend[:15])}{'…' if len(pend) > 15 else ''}"] if pend else []))
    C.append(check("6.1.3 d)", "Declaración de Aplicabilidad con justificación de inclusiones y exclusiones", est, det, items))

    sin_plan = [r["codigo"] for r in rs if r["tratamiento"] in ("Mitigar", "Transferir", "Evitar") and not r["plan_tratamiento"].strip()]
    C.append(check("6.1.3 e)", "Plan de tratamiento formulado", "cumple" if not sin_plan else "falta",
                   "Los riesgos tratados tienen plan documentado." if not sin_plan else "Riesgos con tratamiento sin plan.", sin_plan))

    tratados = [r for r in rs if r["tratamiento"]]
    sin_res = [r["codigo"] for r in tratados if r["tratamiento"] != "Aceptar" and not r["nivel_residual"]["valor"]]
    sin_apr = [r["codigo"] for r in tratados if not r["aprobado_dueno"]]
    res_alto = [f'{r["codigo"]} ({r["nivel_residual"]["valor"]})' for r in tratados if (r["nivel_residual"]["valor"] or 0) > ap]
    C.append(check("6.1.3 f)", "Aprobación del dueño y aceptación del riesgo residual",
                   "cumple" if not sin_res and not sin_apr else "falta",
                   "Riesgo residual estimado y aprobado por cada dueño." if not sin_res and not sin_apr
                   else "Faltan estimaciones de riesgo residual o aprobaciones del dueño.",
                   [f"Sin residual: {x}" for x in sin_res] + [f"Sin aprobación: {x}" for x in sin_apr]))
    if res_alto:
        C.append(check("6.1.3 f)", "Riesgo residual sobre el apetito", "alerta",
                       "El dueño aceptó un residual sobre el apetito; debe quedar escalado y justificado ante la dirección (9.3).", res_alto))

    vencidos = [f'{r["codigo"]} ({r["proxima_revision"]})' for r in rs
                if r["proxima_revision"] and r["proxima_revision"] < hoy and r["estado"] != "Cerrado"]
    C.append(check("8.2", "Evaluación de riesgos a intervalos planificados", "cumple" if not vencidos else "alerta",
                   f"Frecuencia planificada: cada {p['frecuencia_revision_dias']} días." + (" Revisiones vencidas:" if vencidos else ""), vencidos))

    en_trat = [r for r in rs if r["tratamiento"] in ("Mitigar", "Transferir", "Evitar")]
    ctrl_ap = [s for s in sa if s["aplicable"]]
    impl = sum(1 for s in ctrl_ap if s["estado_implementacion"] == "Implementado")
    C.append(check("8.3", "Implementación del plan de tratamiento",
                   "cumple" if ctrl_ap and impl == len(ctrl_ap) else "alerta",
                   f"{impl} de {len(ctrl_ap)} controles aplicables implementados; {sum(1 for r in en_trat if r['estado'] in ('Monitoreo', 'Cerrado'))} de {len(en_trat)} riesgos tratados ya en monitoreo o cerrados."))

    sin_seg = [r["codigo"] for r in rs if not r["ultima_revision"] and r["estado"] != "Cerrado"]
    C.append(check("9.1", "Seguimiento y medición de los riesgos", "cumple" if not sin_seg else "alerta",
                   "Todos los riesgos tienen al menos una revisión registrada." if not sin_seg else "Riesgos sin ninguna revisión registrada.", sin_seg))

    with db() as con:
        desv = con.execute(
            """SELECT r.codigo, v.fecha, v.desviacion_tipo, v.accion FROM revisiones v JOIN riesgos r ON r.id=v.riesgo_id
            WHERE r.proyecto_id=? AND v.desviacion_tipo NOT IN ('', 'Ninguna')""", (pid,)).fetchall()
    sin_acc = [f'{d["codigo"]} {d["fecha"]} ({d["desviacion_tipo"]})' for d in desv if not (d["accion"] or "").strip()]
    rep = {}
    for d in desv:
        rep[d["codigo"]] = rep.get(d["codigo"], 0) + 1
    repetidas = [f"{k}: {v} desviaciones" for k, v in rep.items() if v > 1]
    C.append(check("10.2", "Desviaciones tratadas con acción correctiva", "cumple" if not sin_acc else "falta",
                   f"{len(desv)} desviaciones registradas." + (" Desviaciones repetidas indican que el tratamiento no es eficaz." if repetidas else ""),
                   [f"Sin acción: {x}" for x in sin_acc] + repetidas))

    s58 = next(s for s in sa if s["id"] == "5.8")
    C.append(check("A.5.8", "Seguridad de la información integrada en la gestión del proyecto",
                   "cumple" if s58["aplicable"] else "alerta",
                   "El control 5.8 está declarado aplicable." if s58["aplicable"]
                   else "Todo proyecto debería declarar aplicable el control 5.8 del Anexo A."))

    pesos = {"cumple": 1, "alerta": 0.5, "falta": 0}
    pct = round(100 * sum(pesos[c["estado"]] for c in C) / len(C)) if C else 0
    return {"proyecto": p, "porcentaje": pct, "checks": C,
            "resumen": {k: sum(1 for c in C if c["estado"] == k) for k in ("cumple", "alerta", "falta")}}


# ------------------------------------------------------------------ exportar
def csv_resp(nombre: str, filas: List[list]) -> StreamingResponse:
    buf = io.StringIO()
    buf.write("﻿")  # BOM para que Excel respete los acentos
    w = csv.writer(buf, delimiter=";")
    w.writerows(filas)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{nombre}"'})


@app.get("/api/proyectos/{pid}/export/matriz.csv")
def export_matriz(pid: int):
    rs = listar_riesgos(pid)
    filas = [["Código", "Riesgo", "Fase", "Categoría", "Situación de incertidumbre", "Activo", "Amenaza", "Vulnerabilidad", "CID",
              "Dueño", "P", "I", "Nivel inherente", "Clasificación", "Controles existentes", "Tratamiento", "Plan de tratamiento",
              "Controles Anexo A", "P residual", "I residual", "Nivel residual", "Aprobado por dueño", "Estado", "Identificado", "Próxima revisión"]]
    for r in rs:
        filas.append([r["codigo"], r["titulo"], r["fase"], r["categoria"], r["incertidumbre"], r["activo"], r["amenaza"], r["vulnerabilidad"],
                      r["cid"], r["dueno"], r["probabilidad"], r["impacto"], r["nivel_inherente"]["valor"], r["nivel_inherente"]["nombre"],
                      r["controles_existentes"], r["tratamiento"], r["plan_tratamiento"], ", ".join(r["controles"]),
                      r["prob_residual"], r["impacto_residual"], r["nivel_residual"]["valor"], "Sí" if r["aprobado_dueno"] else "No",
                      r["estado"], r["fecha_identificacion"], r["proxima_revision"]])
    return csv_resp(f"matriz_riesgos_proyecto_{pid}.csv", filas)


@app.get("/api/proyectos/{pid}/export/soa.csv")
def export_soa(pid: int):
    filas = [["Control", "Título", "Aplicable", "Justificación", "Riesgos que lo requieren", "Estado de implementación"]]
    for s in soa(pid):
        filas.append([s["id"], s["titulo"], {True: "Sí", False: "No", None: "Pendiente"}[s["aplicable"]],
                      s["justificacion"], ", ".join(s["riesgos"]), s["estado_implementacion"]])
    return csv_resp(f"declaracion_aplicabilidad_proyecto_{pid}.csv", filas)


@app.get("/api/proyectos/{pid}/export/revisiones.csv")
def export_revisiones(pid: int):
    with db() as con:
        rows = con.execute("""SELECT r.codigo, r.titulo, v.* FROM revisiones v JOIN riesgos r ON r.id=v.riesgo_id
                              WHERE r.proyecto_id=? ORDER BY r.codigo, v.fecha""", (pid,)).fetchall()
    filas = [["Código", "Riesgo", "Fecha", "Revisor", "P", "I", "Nivel", "Estado", "Tipo de desviación", "Detalle", "Acción", "Comentario"]]
    for v in rows:
        filas.append([v["codigo"], v["titulo"], v["fecha"], v["revisor"], v["probabilidad"], v["impacto"],
                      v["probabilidad"] * v["impacto"], v["estado"], v["desviacion_tipo"], v["desviacion_detalle"], v["accion"], v["comentario"]])
    return csv_resp(f"registro_revisiones_proyecto_{pid}.csv", filas)


@app.post("/api/reiniciar-demo")
def reiniciar_demo():
    """Borra todo y vuelve a cargar el proyecto de demostración."""
    with db() as con:
        con.executescript("DELETE FROM soa; DELETE FROM revisiones; DELETE FROM riesgos; DELETE FROM proyectos;")
        sembrar_demo(con)
    return {"ok": True}


# ------------------------------------------------------------------ frontend
if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(FRONTEND / "index.html")
