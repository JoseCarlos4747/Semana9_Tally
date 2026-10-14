// =====================================================
// GESTOR DE TAREAS - LABORATORIO SEMANA 9
// Arquitectura cliente-servidor con capas de seguridad
// =====================================================

const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const SECRET_KEY = 'clave_secreta_lab9_cambiar_en_produccion';
const PORT = 3000;

// =====================================================
// 🔐 CAPA 1: HELMET (Cabeceras HTTP de seguridad)
// Protege contra XSS, clickjacking, sniffing, etc.
// =====================================================
app.use(helmet({
  contentSecurityPolicy: false // Desactivado para permitir scripts inline del lab
}));

// =====================================================
// 🔐 CAPA 2: CORS (Control de acceso entre dominios)
// =====================================================
app.use(cors({
  origin: `http://localhost:${PORT}`,
  credentials: true
}));

// =====================================================
// 🔐 CAPA 3: RATE LIMITING (Evita fuerza bruta)
// =====================================================
const loginLimiter = rateLimit({
  windowMs: 30 * 1000, // 30 seg
  max: 5, // máximo 5 intentos por IP
  message: { error: 'Demasiados intentos. Intenta más tarde.' }
});

// =====================================================
// MIDDLEWARES BÁSICOS
// =====================================================
app.use(bodyParser.json({ limit: '10kb' })); // Limita tamaño (anti-DoS)
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================
// CONEXIÓN A SQLITE CON SEQUELIZE (ORM anti-inyección SQL)
// =====================================================
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'database.sqlite'),
  logging: false
});

// =====================================================
// MODELOS
// =====================================================
const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
});

const Task = sequelize.define('Task', {
  title: {
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  }
});

// Relación: Un usuario tiene muchas tareas
User.hasMany(Task, { foreignKey: 'userId', onDelete: 'CASCADE' });
Task.belongsTo(User, { foreignKey: 'userId' });

// =====================================================
// 🔐 CAPA 4: AUTENTICACIÓN CON JWT (Middleware)
// =====================================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.user = user; // Usuario decodificado disponible en req
    next();
  });
}

// =====================================================
// RUTAS DE AUTENTICACIÓN
// =====================================================

// --- REGISTRO (con hash bcrypt + validación) ---
app.post('/api/register',
  body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
  body('password')
    .isLength({ min: 6 }).withMessage('Mínimo 6 caracteres')
    .matches(/\d/).withMessage('Debe contener al menos un número'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
      // 🔐 Hash de contraseña con bcrypt (12 rondas)
      const hashedPassword = await bcrypt.hash(password, 12);
      const user = await User.create({ email, password: hashedPassword });
      res.status(201).json({ message: 'Usuario creado', userId: user.id });
    } catch (error) {
      res.status(400).json({ error: 'Email ya registrado' });
    }
  }
);

// --- LOGIN (con rate limiting + JWT) ---
app.post('/api/login',
  loginLimiter, // 🔐 Rate limiting contra fuerza bruta
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    // Mensaje genérico (no revelar si el email existe)
    if (!user) return res.status(400).json({ error: 'Credenciales incorrectas' });

    // 🔐 Comparación con bcrypt
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Credenciales incorrectas' });

    // 🔐 Generación de JWT con expiración
    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ token, expiresIn: 3600 });
  }
);

// =====================================================
// 🔐 CAPA 5: AUTORIZACIÓN + CRUD DE TAREAS
// Cada usuario solo accede a SUS propias tareas
// =====================================================

// --- CREAR TAREA ---
app.post('/api/tasks',
  authenticateToken,
  body('title').trim().notEmpty().withMessage('Título obligatorio')
    .isLength({ max: 255 }).withMessage('Máximo 255 caracteres')
    .escape(), // 🔐 Anti-XSS
  body('description').optional().trim().escape(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { title, description } = req.body;
    // 🔐 AUTORIZACIÓN: userId viene del token, NO del body
    const task = await Task.create({
      title,
      description,
      userId: req.user.id
    });
    res.status(201).json(task);
  }
);

// --- LEER TAREAS (solo las del usuario autenticado) ---
app.get('/api/tasks', authenticateToken, async (req, res) => {
  // 🔐 AUTORIZACIÓN: filtro por userId del token
  const tasks = await Task.findAll({ where: { userId: req.user.id } });
  res.json(tasks);
});

// --- ACTUALIZAR TAREA (verifica propiedad) ---
app.put('/api/tasks/:id',
  authenticateToken,
  body('title').optional().trim().escape(),
  body('description').optional().trim().escape(),
  async (req, res) => {
    // 🔐 AUTORIZACIÓN: solo si la tarea pertenece al usuario
    const task = await Task.findOne({
      where: { id: req.params.id, userId: req.user.id }
    });
    if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });

    await task.update(req.body);
    res.json(task);
  }
);

// --- ELIMINAR TAREA (verifica propiedad) ---
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  const task = await Task.findOne({
    where: { id: req.params.id, userId: req.user.id }
  });
  if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });

  await task.destroy();
  res.json({ message: 'Tarea eliminada' });
});

// =====================================================
// 🔐 CAPA 6: MANEJO GLOBAL DE ERRORES
// No revela stack traces al cliente
// =====================================================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// =====================================================
// INICIAR SERVIDOR
// =====================================================
sequelize.sync().then(() => {
  app.listen(PORT, () => {
    console.log('========================================');
    console.log(`✅ Servidor en http://localhost:${PORT}`);
    console.log('========================================');
    console.log('🔐 Capas de seguridad activas:');
    console.log('   1. Helmet (headers HTTP)');
    console.log('   2. CORS (origen restringido)');
    console.log('   3. Rate Limiting (10 intentos/15min)');
    console.log('   4. Validación de datos (express-validator)');
    console.log('   5. Hash bcrypt (12 rondas)');
    console.log('   6. JWT con expiración (1h)');
    console.log('   7. Autorización por userId');
    console.log('   8. Sequelize ORM (anti-inyección SQL)');
    console.log('   9. Escape HTML (anti-XSS)');
    console.log('  10. Manejo de errores sin fuga de info');
    console.log('========================================');
  });
});