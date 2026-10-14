// =====================================================
// FRONTEND - GESTOR DE TAREAS LAB 9
// =====================================================

const API = 'http://localhost:3000/api';

// Helper para mostrar mensajes
function mostrarMensaje(texto, tipo = 'error') {
  const el = document.getElementById('mensaje');
  if (!el) return;
  el.textContent = texto;
  el.className = tipo === 'success' ? 'success' : '';
}

// =====================================================
// REGISTRO
// =====================================================
if (document.getElementById('registerForm')) {
  document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    if (password.length < 6) {
      return mostrarMensaje('La contraseña debe tener al menos 6 caracteres');
    }

    try {
      const res = await fetch(`${API}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok) {
        mostrarMensaje('✅ Usuario creado. Redirigiendo al login...', 'success');
        setTimeout(() => window.location.href = 'login.html', 1500);
      } else {
        const msg = data.errors ? data.errors[0].msg : (data.error || 'Error al registrar');
        mostrarMensaje(msg);
      }
    } catch (err) {
      mostrarMensaje('Error de conexión con el servidor');
    }
  });
}

// =====================================================
// LOGIN
// =====================================================
if (document.getElementById('loginForm')) {
  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    try {
      const res = await fetch(`${API}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok) {
        // 🔐 Guardar JWT en localStorage
        localStorage.setItem('jwt', data.token);
        window.location.href = 'tasks.html';
      } else {
        mostrarMensaje(data.error || 'Credenciales incorrectas');
      }
    } catch (err) {
      mostrarMensaje('Error de conexión con el servidor');
    }
  });
}

// =====================================================
// TAREAS (CRUD)
// =====================================================
if (document.getElementById('taskForm')) {
  const token = localStorage.getItem('jwt');
  if (!token) {
    window.location.href = 'login.html';
  } else {
    cargarTareas();

    document.getElementById('taskForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('taskTitle').value.trim();
      const description = document.getElementById('taskDesc').value.trim();

      if (!title) return mostrarMensaje('El título es obligatorio');

      try {
        const res = await fetch(`${API}/tasks`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ title, description })
        });

        if (res.status === 401 || res.status === 403) {
          return cerrarSesion();
        }

        if (res.ok) {
          document.getElementById('taskTitle').value = '';
          document.getElementById('taskDesc').value = '';
          mostrarMensaje('Tarea agregada', 'success');
          cargarTareas();
        } else {
          const data = await res.json();
          mostrarMensaje(data.error || 'Error al crear tarea');
        }
      } catch (err) {
        mostrarMensaje('Error de conexión');
      }
    });

    document.getElementById('logoutBtn').addEventListener('click', cerrarSesion);
  }
}

// =====================================================
// FUNCIONES AUXILIARES
// =====================================================
async function cargarTareas() {
  const token = localStorage.getItem('jwt');
  if (!token) return window.location.href = 'login.html';

  try {
    const res = await fetch(`${API}/tasks`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (res.status === 401 || res.status === 403) {
      return cerrarSesion();
    }

    const tareas = await res.json();
    const lista = document.getElementById('taskList');
    lista.innerHTML = '';

    if (tareas.length === 0) {
      lista.innerHTML = '<li style="justify-content:center;color:#888;border-left-color:#ccc;">No tienes tareas aún. ¡Agrega una!</li>';
      return;
    }

    tareas.forEach(tarea => {
      const li = document.createElement('li');
      const span = document.createElement('span');
      const strong = document.createElement('strong');
      strong.textContent = tarea.title;
      span.appendChild(strong);
      if (tarea.description) {
        span.appendChild(document.createTextNode(` — ${tarea.description}`));
      }
      li.appendChild(span);

      const btn = document.createElement('button');
      btn.textContent = '❌';
      btn.onclick = () => eliminarTarea(tarea.id);
      li.appendChild(btn);

      lista.appendChild(li);
    });
  } catch (err) {
    mostrarMensaje('Error al cargar tareas');
  }
}

async function eliminarTarea(id) {
  const token = localStorage.getItem('jwt');
  if (!confirm('¿Eliminar esta tarea?')) return;

  try {
    const res = await fetch(`${API}/tasks/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (res.status === 401 || res.status === 403) return cerrarSesion();

    if (res.ok) {
      mostrarMensaje('Tarea eliminada', 'success');
      cargarTareas();
    }
  } catch (err) {
    mostrarMensaje('Error al eliminar');
  }
}

function cerrarSesion() {
  localStorage.removeItem('jwt');
  window.location.href = 'login.html';
}