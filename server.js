const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_de_prueba';
const TOKEN_TTL = '1h';

const TASKS_FILE = path.join(__dirname, 'tareas.json');
const USERS_FILE = path.join(__dirname, 'usuarios.json');

// ---------- Utilidades de persistencia (fs asíncrono) ----------

// Cola por archivo: serializa las escrituras para evitar condiciones de carrera
// entre peticiones concurrentes (el Event Loop puede intercalarlas en cada await).
const colas = new Map();
function enCola(file, fn) {
  const previa = colas.get(file) || Promise.resolve();
  const siguiente = previa.then(fn, fn);
  colas.set(file, siguiente.catch(() => {}));
  return siguiente;
}

async function leerJSON(file) {
  try {
    const data = await fs.readFile(file, 'utf8');
    return data.trim() ? JSON.parse(data) : [];
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

async function escribirJSON(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2), 'utf8');
}

// Lee-modifica-escribe de forma atómica respecto a otras peticiones
function modificar(file, mutador) {
  return enCola(file, async () => {
    const data = await leerJSON(file);
    const resultado = await mutador(data);
    await escribirJSON(file, data);
    return resultado;
  });
}

// ---------- Errores personalizados ----------

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------- Middleware ----------

app.use(express.json());

// Logger simple (útil para debugging)
app.use((req, res, next) => {
  const inicio = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - inicio}ms)`);
  });
  next();
});

// Autenticación: exige "Authorization: Bearer <token>"
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [tipo, token] = header.split(' ');
  if (tipo !== 'Bearer' || !token) {
    return next(new HttpError(401, 'Token de autenticación requerido'));
  }
  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    next(new HttpError(401, 'Token inválido o expirado'));
  }
}

// Validación de credenciales (registro/login)
function validarCredenciales(req, res, next) {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || username.trim().length < 3) {
    return next(new HttpError(400, 'username debe ser texto de al menos 3 caracteres'));
  }
  if (typeof password !== 'string' || password.length < 6) {
    return next(new HttpError(400, 'password debe tener al menos 6 caracteres'));
  }
  req.body.username = username.trim();
  next();
}

// Validación de tareas. Con parcial=true (PUT) los campos son opcionales,
// pero debe venir al menos uno.
function validarTarea(parcial = false) {
  return (req, res, next) => {
    const { titulo, descripcion, completada } = req.body || {};

    if (!parcial || titulo !== undefined) {
      if (typeof titulo !== 'string' || titulo.trim() === '') {
        return next(new HttpError(400, 'titulo es obligatorio y debe ser texto no vacío'));
      }
    }
    if (!parcial && (typeof descripcion !== 'string' || descripcion.trim() === '')) {
      return next(new HttpError(400, 'descripcion es obligatoria y debe ser texto no vacío'));
    }
    if (descripcion !== undefined && typeof descripcion !== 'string') {
      return next(new HttpError(400, 'descripcion debe ser texto'));
    }
    if (completada !== undefined && typeof completada !== 'boolean') {
      return next(new HttpError(400, 'completada debe ser booleano'));
    }
    if (parcial && titulo === undefined && descripcion === undefined && completada === undefined) {
      return next(new HttpError(400, 'Envía al menos un campo: titulo, descripcion o completada'));
    }
    next();
  };
}

function validarId(req, res, next) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return next(new HttpError(400, 'El id debe ser un entero positivo'));
  }
  req.id = id;
  next();
}

// ---------- Rutas públicas: autenticación ----------

app.post('/registro', validarCredenciales, async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const usuario = await modificar(USERS_FILE, (usuarios) => {
    if (usuarios.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
      throw new HttpError(409, 'El usuario ya existe');
    }
    const nuevo = {
      id: usuarios.length ? Math.max(...usuarios.map((u) => u.id)) + 1 : 1,
      username,
      password: hash,
    };
    usuarios.push(nuevo);
    return nuevo;
  });

  res.status(201).json({ id: usuario.id, username: usuario.username });
});

app.post('/login', validarCredenciales, async (req, res) => {
  const { username, password } = req.body;
  const usuarios = await leerJSON(USERS_FILE);
  const usuario = usuarios.find((u) => u.username.toLowerCase() === username.toLowerCase());

  if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
    throw new HttpError(401, 'Credenciales incorrectas');
  }

  const token = jwt.sign({ id: usuario.id, username: usuario.username }, JWT_SECRET, {
    expiresIn: TOKEN_TTL,
  });
  res.json({ mensaje: 'Sesión iniciada', token });
});

// ---------- Rutas protegidas: CRUD de tareas ----------

const tareas = express.Router();
tareas.use(autenticar);

// Leer todas (opcional: ?completada=true|false)
tareas.get('/', async (req, res) => {
  let lista = (await leerJSON(TASKS_FILE)).filter((t) => t.usuarioId === req.usuario.id);
  if (req.query.completada !== undefined) {
    const filtro = req.query.completada === 'true';
    lista = lista.filter((t) => t.completada === filtro);
  }
  res.json(lista);
});

// Leer una
tareas.get('/:id', validarId, async (req, res) => {
  const lista = await leerJSON(TASKS_FILE);
  const tarea = lista.find((t) => t.id === req.id && t.usuarioId === req.usuario.id);
  if (!tarea) throw new HttpError(404, 'Tarea no encontrada');
  res.json(tarea);
});

// Crear
tareas.post('/', validarTarea(false), async (req, res) => {
  const { titulo, descripcion, completada = false } = req.body;
  const nueva = await modificar(TASKS_FILE, (lista) => {
    const tarea = {
      id: lista.length ? Math.max(...lista.map((t) => t.id)) + 1 : 1,
      usuarioId: req.usuario.id,
      titulo: titulo.trim(),
      descripcion: descripcion.trim(),
      completada,
      creada: new Date().toISOString(),
    };
    lista.push(tarea);
    return tarea;
  });
  res.status(201).json(nueva);
});

// Actualizar
tareas.put('/:id', validarId, validarTarea(true), async (req, res) => {
  const { titulo, descripcion, completada } = req.body;
  const actualizada = await modificar(TASKS_FILE, (lista) => {
    const tarea = lista.find((t) => t.id === req.id && t.usuarioId === req.usuario.id);
    if (!tarea) throw new HttpError(404, 'Tarea no encontrada');
    if (titulo !== undefined) tarea.titulo = titulo.trim();
    if (descripcion !== undefined) tarea.descripcion = descripcion;
    if (completada !== undefined) tarea.completada = completada;
    tarea.actualizada = new Date().toISOString();
    return tarea;
  });
  res.json(actualizada);
});

// Eliminar
tareas.delete('/:id', validarId, async (req, res) => {
  await modificar(TASKS_FILE, (lista) => {
    const i = lista.findIndex((t) => t.id === req.id && t.usuarioId === req.usuario.id);
    if (i === -1) throw new HttpError(404, 'Tarea no encontrada');
    lista.splice(i, 1);
  });
  res.status(204).end();
});

app.use('/tareas', tareas);

// ---------- Manejo de errores ----------

// 404 para rutas inexistentes
app.use((req, res, next) => {
  next(new HttpError(404, `Ruta ${req.method} ${req.originalUrl} no encontrada`));
});

// Middleware de errores (4 argumentos). Express 5 envía aquí también
// los errores de handlers async.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    err = new HttpError(400, 'JSON inválido en el cuerpo de la petición');
  }
  const status = err.status || 500;
  if (status >= 500) console.error(err); // stack solo en consola, para debugging
  res.status(status).json({
    error: status >= 500 ? 'Error interno del servidor' : err.message,
  });
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});

// node server.js
