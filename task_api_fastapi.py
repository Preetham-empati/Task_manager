from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
import datetime

# ----------------------
# Database Setup
# ----------------------
DATABASE_URL = "sqlite:///./tasks.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------------
# Models
# ----------------------
class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# ----------------------
# Pydantic Schemas (Pydantic v2 compatible)
# ----------------------
class TaskCreate(BaseModel):
    title: str
    description: str

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    description: str

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str

# ----------------------
# Auth Setup (JWT)
# ----------------------
SECRET_KEY = "mysecretkey"  # For demo only. Use env vars in production.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----------------------
# Dependencies
# ----------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ----------------------
# FastAPI App
# ----------------------
app = FastAPI(
    title="Task Management API",
    version="1.1.0",
    description="A simple, secure Task API with a built-in mini UI."
)

# CORS (allow frontends)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Auth Endpoints
# ----------------------
@app.post("/register", response_model=UserResponse, tags=["Auth"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Basic duplicate check
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# ----------------------
# Task Endpoints
# ----------------------
@app.post("/tasks/", response_model=TaskResponse, tags=["Tasks"])
def create_task(task: TaskCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_task = Task(title=task.title, description=task.description)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get("/tasks/", response_model=List[TaskResponse], tags=["Tasks"])
def read_tasks(
    skip: int = 0,
    limit: int = 10,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Task)
    if q:
        like = f"%{q}%"
        query = query.filter((Task.title.like(like)) | (Task.description.like(like)))
    tasks = query.offset(skip).limit(limit).all()
    return tasks

@app.get("/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
def read_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.put("/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
def update_task(task_id: int, task_update: TaskUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task_update.title is not None:
        task.title = task_update.title
    if task_update.description is not None:
        task.description = task_update.description
    db.commit()
    db.refresh(task)
    return task

@app.delete("/tasks/{task_id}", tags=["Tasks"])
def delete_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(task)
    db.commit()
    return {"message": "Task deleted successfully"}

# ----------------------
# Mini Frontend (Beautiful, functional UI)
# ----------------------
@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def ui_home():
    return """
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>Task Manager API</title>
  <script src=\"https://cdn.tailwindcss.com\"></script>
  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"> 
  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">
  <style>
    html, body { height: 100%; }
    body { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }
    .card { @apply bg-slate-800/60 backdrop-blur rounded-2xl shadow-xl border border-slate-700; }
    .btn { @apply px-4 py-2 rounded-xl shadow transition; }
    .btn-primary { @apply bg-orange-500 hover:bg-orange-600 text-white; }
    .btn-ghost { @apply bg-slate-700 hover:bg-slate-600 text-slate-100; }
    .input { @apply w-full px-4 py-2 rounded-xl bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500; }
    .link { @apply text-orange-400 hover:text-orange-300; }
  </style>
</head>
<body class=\"min-h-full bg-slate-900 text-slate-100\">
  <div class=\"max-w-5xl mx-auto p-6 md:p-10\">
    <header class=\"flex items-center justify-between mb-8\">
      <h1 class=\"text-2xl md:text-3xl font-bold\">🚀 Task Manager API</h1>
      <nav class=\"flex gap-3\">
        <a class=\"btn btn-ghost\" href=\"/docs\">Swagger</a>
        <a class=\"btn btn-ghost\" href=\"/redoc\">ReDoc</a>
        <button id=\"logoutBtn\" class=\"btn btn-ghost hidden\">Logout</button>
      </nav>
    </header>

    <!-- Auth & App Cards -->
    <div id=\"authCard\" class=\"card p-6 md:p-8\">
      <div class=\"flex flex-wrap gap-4 items-center justify-between mb-6\">
        <h2 class=\"text-xl font-semibold\">Sign in or create an account</h2>
        <p class=\"text-slate-400 text-sm\">Use the same credentials for the API docs (Authorize) ⚙️</p>
      </div>

      <div class=\"grid md:grid-cols-2 gap-6\">
        <form id=\"loginForm\" class=\"space-y-3\">
          <h3 class=\"font-semibold\">Login</h3>
          <input class=\"input\" name=\"username\" placeholder=\"Username\" required />
          <input class=\"input\" type=\"password\" name=\"password\" placeholder=\"Password\" required />
          <button class=\"btn btn-primary w-full\" type=\"submit\">Login</button>
          <p id=\"loginMsg\" class=\"text-sm text-slate-300\"></p>
        </form>

        <form id=\"registerForm\" class=\"space-y-3\">
          <h3 class=\"font-semibold\">Register</h3>
          <input class=\"input\" name=\"username\" placeholder=\"Choose a username\" required />
          <input class=\"input\" type=\"password\" name=\"password\" placeholder=\"Choose a password\" required />
          <button class=\"btn btn-ghost w-full\" type=\"submit\">Create account</button>
          <p id=\"registerMsg\" class=\"text-sm text-slate-300\"></p>
        </form>
      </div>
    </div>

    <div id=\"appCard\" class=\"card p-6 md:p-8 hidden\">
      <div class=\"flex flex-col md:flex-row md:items-center gap-3 justify-between mb-6\">
        <h2 class=\"text-xl font-semibold\">Your Tasks</h2>
        <div class=\"flex gap-2\">
          <input id=\"searchInput\" class=\"input\" placeholder=\"Search by title or description\" />
          <button id=\"searchBtn\" class=\"btn btn-ghost\">Search</button>
        </div>
      </div>

      <form id=\"createForm\" class=\"grid md:grid-cols-3 gap-3 mb-6\">
        <input class=\"input\" name=\"title\" placeholder=\"Task title\" required />
        <input class=\"input\" name=\"description\" placeholder=\"Task description\" required />
        <button class=\"btn btn-primary\" type=\"submit\">Add Task</button>
      </form>

      <div id=\"list\" class=\"space-y-3\"></div>

      <div class=\"flex items-center justify-between mt-6\">
        <button id=\"prevBtn\" class=\"btn btn-ghost\">Prev</button>
        <span id=\"pageInfo\" class=\"text-slate-400 text-sm\"></span>
        <button id=\"nextBtn\" class=\"btn btn-ghost\">Next</button>
      </div>
    </div>
  </div>

<script>
  const state = {
    token: localStorage.getItem('token') || null,
    skip: 0,
    limit: 10,
    q: ''
  };

  const el = id => document.getElementById(id);
  const authCard = el('authCard');
  const appCard = el('appCard');
  const logoutBtn = el('logoutBtn');
  const loginForm = el('loginForm');
  const registerForm = el('registerForm');
  const loginMsg = el('loginMsg');
  const registerMsg = el('registerMsg');
  const createForm = el('createForm');
  const list = el('list');
  const pageInfo = el('pageInfo');
  const prevBtn = el('prevBtn');
  const nextBtn = el('nextBtn');
  const searchInput = el('searchInput');
  const searchBtn = el('searchBtn');

  function setAuthUI(loggedIn) {
    if (loggedIn) {
      authCard.classList.add('hidden');
      appCard.classList.remove('hidden');
      logoutBtn.classList.remove('hidden');
    } else {
      authCard.classList.remove('hidden');
      appCard.classList.add('hidden');
      logoutBtn.classList.add('hidden');
    }
  }

  async function api(path, options = {}) {
    const headers = options.headers || {};
    if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
    if (!(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { ...options, headers });
    if (!res.ok) {
      const msg = await res.text();
      throw new Error(msg || res.statusText);
    }
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? res.json() : res.text();
  }

  async function loadTasks() {
    try {
      const query = new URLSearchParams({ skip: state.skip, limit: state.limit, q: state.q || '' }).toString();
      const data = await api(`/tasks/?${query}`);
      renderList(data);
      pageInfo.textContent = `Showing ${data.length} items (skip ${state.skip})`;
    } catch (e) {
      console.error(e);
      alert('Failed to load tasks. Are you logged in?');
    }
  }

  function renderList(tasks) {
    list.innerHTML = '';
    if (!tasks.length) {
      list.innerHTML = `<p class=\"text-slate-400\">No tasks found.</p>`;
      return;
    }
    tasks.forEach(t => {
      const row = document.createElement('div');
      row.className = 'card p-4 flex flex-col md:flex-row md:items-center gap-3 justify-between';
      row.innerHTML = `
        <div class=\"flex-1\">
          <input class=\"input mb-2 md:mb-0\" value=\"${t.title.replaceAll('"','&quot;')}\" data-id=\"${t.id}\" data-field=\"title\" />
          <input class=\"input mt-2 md:mt-0\" value=\"${t.description.replaceAll('"','&quot;')}\" data-id=\"${t.id}\" data-field=\"description\" />
        </div>
        <div class=\"flex gap-2\">
          <button class=\"btn btn-primary\" data-action=\"save\" data-id=\"${t.id}\">Save</button>
          <button class=\"btn btn-ghost\" data-action=\"delete\" data-id=\"${t.id}\">Delete</button>
        </div>`;
      list.appendChild(row);
    });
  }

  // Event Listeners
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginMsg.textContent = 'Logging in...';
    const fd = new FormData(loginForm);
    const body = new URLSearchParams();
    body.set('username', fd.get('username'));
    body.set('password', fd.get('password'));
    body.set('grant_type', 'password');
    try {
      const res = await fetch('/token', { method: 'POST', body });
      if (!res.ok) throw new Error('Invalid credentials');
      const data = await res.json();
      state.token = data.access_token;
      localStorage.setItem('token', state.token);
      loginMsg.textContent = 'Logged in ✅';
      setAuthUI(true);
      await loadTasks();
    } catch (err) {
      loginMsg.textContent = 'Login failed ❌';
    }
  });

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    registerMsg.textContent = 'Creating account...';
    const fd = new FormData(registerForm);
    try {
      await api('/register', { method: 'POST', body: JSON.stringify({
        username: fd.get('username'), password: fd.get('password')
      })});
      registerMsg.textContent = 'Account created ✅ You can now login';
    } catch (err) {
      registerMsg.textContent = 'Registration failed ❌ (maybe username exists)';
    }
  });

  createForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(createForm);
    try {
      await api('/tasks/', { method: 'POST', body: JSON.stringify({
        title: fd.get('title'), description: fd.get('description')
      })});
      createForm.reset();
      await loadTasks();
    } catch (err) {
      alert('Failed to create task');
    }
  });

  list.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const id = btn.getAttribute('data-id');
    const action = btn.getAttribute('data-action');

    if (action === 'delete') {
      if (!confirm('Delete this task?')) return;
      try { await api(`/tasks/${id}`, { method: 'DELETE' }); await loadTasks(); }
      catch { alert('Delete failed'); }
      return;
    }

    if (action === 'save') {
      const fields = list.querySelectorAll(`[data-id="${id}"]`);
      const payload = {};
      fields.forEach(f => payload[f.getAttribute('data-field')] = f.value);
      try { await api(`/tasks/${id}`, { method: 'PUT', body: JSON.stringify(payload) }); alert('Saved ✅'); }
      catch { alert('Save failed'); }
    }
  });

  prevBtn.addEventListener('click', () => {
    state.skip = Math.max(0, state.skip - state.limit); loadTasks();
  });
  nextBtn.addEventListener('click', () => {
    state.skip = state.skip + state.limit; loadTasks();
  });

  searchBtn.addEventListener('click', () => {
    state.q = searchInput.value.trim(); state.skip = 0; loadTasks();
  });

  logoutBtn.addEventListener('click', () => {
    state.token = null; localStorage.removeItem('token'); setAuthUI(false);
  });

  // Init
  if (state.token) { setAuthUI(true); loadTasks(); } else { setAuthUI(false); }
</script>
</body>
</html>
    """
