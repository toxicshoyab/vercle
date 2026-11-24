from flask import Flask, render_template_string, request, redirect, url_for, session, abort
import sqlite3
import hashlib
import hmac
import os
import secrets
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('STUD4YOU_SECRET_KEY', 'stud4you_secure_portal_key_2026_v2')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_IMAGES = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_PDFS = {'pdf'}
ALLOWED_POST_FILES = ALLOWED_IMAGES | ALLOWED_PDFS
ALLOWED_THEMES = {'dark', 'light', 'slate', 'chalkboard'}


def get_db():
    conn = sqlite3.connect('nexus.db', timeout=15)
    conn.execute('PRAGMA foreign_keys = ON;')
    conn.execute('PRAGMA journal_mode = WAL;')
    return conn


def is_image_file(filename):
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGES


def is_pdf_file(filename):
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_PDFS


def save_validated_upload(file_storage, allowed_exts):
    if not file_storage or not file_storage.filename:
        return None, None
    clean_name = secure_filename(file_storage.filename)
    if '.' not in clean_name:
        return None, "File must have a valid extension."
    ext = clean_name.rsplit('.', 1)[1].lower()
    if ext not in allowed_exts:
        return None, f"Unsupported file type '.{ext}'. Allowed: {', '.join(sorted(allowed_exts))}."

    # Read header bytes to check signature for PDFs and images
    header = file_storage.stream.read(12)
    file_storage.stream.seek(0)

    if ext == 'pdf' and not header.startswith(b'%PDF-'):
        return None, "Invalid PDF file header."
    if ext in {'jpg', 'jpeg'} and not header.startswith(b'\xff\xd8\xff'):
        return None, "Invalid JPEG image file."
    if ext == 'png' and not header.startswith(b'\x89PNG\r\n\x1a\n'):
        return None, "Invalid PNG image file."
    if ext == 'gif' and not (header.startswith(b'GIF87a') or header.startswith(b'GIF89a')):
        return None, "Invalid GIF image file."
    if ext == 'webp' and not (header.startswith(b'RIFF') and b'WEBP' in header):
        return None, "Invalid WEBP image file."

    stored_name = f"{uuid.uuid4().hex}_{clean_name}"
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_name))
    return stored_name, None


def get_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf():
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    expected = session.get('_csrf_token')
    if not token or not expected or not hmac.compare_digest(str(token), str(expected)):
        abort(403, description="Invalid or missing CSRF token.")


# ================= ROBUST SELF-MIGRATING DATABASE INIT =================
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT 'default.png',
            bio TEXT DEFAULT 'Passionate student exploring technology and science.',
            institution TEXT DEFAULT 'University of Technology',
            education TEXT DEFAULT 'B.Sc. Computer Science (2024 - 2028)',
            achievements TEXT DEFAULT 'Dean Honors List, Hackathon Finalist',
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    existing_columns = [col[1] for col in cursor.execute("PRAGMA table_info(users)").fetchall()]
    migrations = [
        ('avatar', "TEXT DEFAULT 'default.png'"),
        ('bio', "TEXT DEFAULT 'Passionate student exploring technology and science.'"),
        ('institution', "TEXT DEFAULT 'University of Technology'"),
        ('education', "TEXT DEFAULT 'B.Sc. Computer Science (2024 - 2028)'"),
        ('achievements', "TEXT DEFAULT 'Dean Honors List, Hackathon Finalist'"),
        ('is_admin', "INTEGER DEFAULT 0")
    ]
    for col_name, col_def in migrations:
        if col_name not in existing_columns:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT,
            filename TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER,
            content TEXT NOT NULL,
            media_file TEXT,
            pdf_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    post_columns = [col[1] for col in cursor.execute("PRAGMA table_info(posts)").fetchall()]
    if 'pdf_file' not in post_columns:
        cursor.execute("ALTER TABLE posts ADD COLUMN pdf_file TEXT")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            user_id INTEGER,
            post_id INTEGER,
            PRIMARY KEY (user_id, post_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author_id INTEGER,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER,
            followed_id INTEGER,
            PRIMARY KEY (follower_id, followed_id),
            FOREIGN KEY (follower_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (followed_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            actor_id INTEGER,
            verb TEXT NOT NULL,
            target_id INTEGER,
            is_read INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    conn.commit()

    # Bootstrap Superadmin with salted Werkzeug hash
    admin_pw = os.environ.get('STUD4YOU_ADMIN_PW', 'shoyab@2006')
    cursor.execute('SELECT id FROM users WHERE username = ?', ('shoyab55555',))
    if not cursor.fetchone():
        hashed_pw = generate_password_hash(admin_pw)
        cursor.execute('''
            INSERT INTO users (username, email, password, bio, institution, education, achievements, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            'shoyab55555',
            'maxiygamer22@gmail.com',
            hashed_pw,
            'System Administrator & Full Stack Developer',
            'Nexus Core Institute',
            'B.Tech Software Engineering',
            'Lead System Architect'
        ))
        conn.commit()
    else:
        cursor.execute('UPDATE users SET is_admin = 1 WHERE username = ?', ('shoyab55555',))
        conn.commit()

    conn.close()


init_db()


def verify_and_upgrade_password(cursor, user_id, stored_hash, plain_password):
    if stored_hash.startswith(('pbkdf2:', 'scrypt:')):
        return check_password_hash(stored_hash, plain_password)
    # Upgrade legacy SHA-256 hashes on successful sign-in
    legacy_sha256 = hashlib.sha256(plain_password.encode()).hexdigest()
    if hmac.compare_digest(stored_hash, legacy_sha256):
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(plain_password), user_id))
        return True
    return False


def log_activity(user_id, action):
    try:
        ip = request.remote_addr or 'unknown'
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO activities (user_id, action, ip_address) VALUES (?, ?, ?)', (user_id, action, ip))
        conn.commit()
        conn.close()
    except Exception:
        pass


def create_notification(user_id, actor_id, verb, target_id=None):
    if user_id == actor_id:
        return
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO notifications (user_id, actor_id, verb, target_id) VALUES (?, ?, ?, ?)',
                       (user_id, actor_id, verb, target_id))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ================= SECURITY HEADERS =================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ================= RESPONSIVE ANIMATED GLASSMORPHIC UI + EDUCATION THEMES =================
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STUD4YOU / Student Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root, [data-theme="dark"] {
            --bg-color: #04060b;
            --panel-bg: rgba(13, 18, 32, 0.84);
            --panel-solid: #0d1220;
            --card-border: rgba(255, 255, 255, 0.08);
            --neon-green: #39ff14;
            --neon-yellow: #ccff00;
            --neon-purple: #b026ff;
            --accent-red: #ff073a;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --glow-green: 0 0 25px rgba(57, 255, 20, 0.25);
            --glow-purple: 0 0 25px rgba(176, 38, 255, 0.25);
            --orb-1: var(--neon-purple);
            --orb-2: var(--neon-green);
        }
        [data-theme="light"] {
            --bg-color: #f1f5f9;
            --panel-bg: rgba(255, 255, 255, 0.92);
            --panel-solid: #ffffff;
            --card-border: rgba(15, 23, 42, 0.1);
            --neon-green: #16a34a;
            --neon-yellow: #ca8a04;
            --neon-purple: #7e22ce;
            --accent-red: #dc2626;
            --text-main: #0f172a;
            --text-dim: #64748b;
            --glow-green: 0 8px 25px rgba(22, 163, 74, 0.15);
            --glow-purple: 0 8px 25px rgba(126, 34, 206, 0.15);
            --orb-1: var(--neon-purple);
            --orb-2: var(--neon-green);
        }
        /* Education Theme 1: Academic Library & Study Hall */
        [data-theme="slate"] {
            --bg-color: #0b132b;
            --panel-bg: rgba(20, 33, 61, 0.88);
            --panel-solid: #14213d;
            --card-border: rgba(125, 211, 252, 0.16);
            --neon-green: #38bdf8;
            --neon-yellow: #fbbf24;
            --neon-purple: #818cf8;
            --accent-red: #f43f5e;
            --text-main: #f1f5f9;
            --text-dim: #cbd5e1;
            --glow-green: 0 0 22px rgba(56, 189, 248, 0.25);
            --glow-purple: 0 0 22px rgba(129, 140, 248, 0.22);
            --orb-1: #38bdf8;
            --orb-2: #fbbf24;
        }
        /* Education Theme 2: Campus Chalkboard & Botanical */
        [data-theme="chalkboard"] {
            --bg-color: #0d241b;
            --panel-bg: rgba(17, 45, 35, 0.9);
            --panel-solid: #112d23;
            --card-border: rgba(254, 240, 138, 0.16);
            --neon-green: #4ade80;
            --neon-yellow: #fde047;
            --neon-purple: #2dd4bf;
            --accent-red: #fb7185;
            --text-main: #f0fdf4;
            --text-dim: #bbf7d0;
            --glow-green: 0 0 22px rgba(74, 222, 128, 0.22);
            --glow-purple: 0 0 22px rgba(45, 212, 191, 0.22);
            --orb-1: #4ade80;
            --orb-2: #fde047;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }

        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: var(--card-border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--neon-purple); }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            position: relative;
            transition: background-color 0.35s ease, color 0.35s ease;
        }

        body::before, body::after {
            content: '';
            position: fixed;
            width: 350px;
            height: 350px;
            border-radius: 50%;
            filter: blur(100px);
            z-index: -1;
            pointer-events: none;
            opacity: 0.28;
            animation: floatOrb 16s infinite alternate ease-in-out;
        }
        body::before { top: -80px; left: -80px; background: radial-gradient(circle, var(--orb-1), transparent 70%); }
        body::after { bottom: -80px; right: -80px; background: radial-gradient(circle, var(--orb-2), transparent 70%); animation-delay: -8s; }

        @keyframes floatOrb {
            0% { transform: translate(0, 0) scale(1); }
            50% { transform: translate(40px, 30px) scale(1.1); }
            100% { transform: translate(-30px, 60px) scale(0.95); }
        }

        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(14px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes pulseBadge {
            0%, 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(255, 7, 58, 0.7); }
            50% { transform: scale(1.08); box-shadow: 0 0 0 6px rgba(255, 7, 58, 0); }
        }

        nav {
            display: flex; justify-content: space-between; align-items: center;
            padding: 0.9rem 1.8rem; background: var(--panel-bg);
            border-bottom: 1px solid var(--card-border);
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.2);
            position: sticky; top: 0; z-index: 100;
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            gap: 0.75rem;
        }
        .brand {
            font-size: 1.3rem; font-weight: 800; text-decoration: none;
            background: linear-gradient(135deg, var(--neon-green), var(--neon-yellow));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px; white-space: nowrap;
        }
        .brand span {
            background: linear-gradient(135deg, var(--neon-yellow), var(--neon-purple));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }

        .nav-links { display: flex; gap: 1.1rem; align-items: center; flex-wrap: wrap; }
        .nav-links a:not(.btn) {
            color: var(--text-main); text-decoration: none; font-weight: 600;
            font-size: 0.88rem; position: relative; padding: 0.25rem 0;
            transition: color 0.25s ease;
        }
        .nav-links a:not(.btn)::after {
            content: ''; position: absolute; left: 0; bottom: 0; width: 0%; height: 2px;
            background: linear-gradient(90deg, var(--neon-green), var(--neon-yellow));
            transition: width 0.3s ease; border-radius: 2px;
        }
        .nav-links a:not(.btn):hover { color: var(--neon-green); }
        .nav-links a:not(.btn):hover::after { width: 100%; }

        .badge-count {
            background: var(--accent-red); color: #fff; font-size: 0.65rem; font-weight: 800;
            padding: 0.1rem 0.4rem; border-radius: 999px; position: absolute;
            top: -6px; right: -12px; animation: pulseBadge 2s infinite;
        }

        .menu-toggle {
            display: none; background: none; border: none; cursor: pointer;
            flex-direction: column; gap: 5px; padding: 5px; z-index: 102;
        }
        .menu-toggle span {
            width: 24px; height: 2px; background: var(--text-main); border-radius: 2px;
            transition: all 0.3s ease;
        }

        .btn {
            position: relative; overflow: hidden;
            background: linear-gradient(135deg, var(--neon-green), var(--neon-yellow));
            color: #04060b; padding: 0.55rem 1.15rem; border-radius: 10px;
            font-weight: 700; text-decoration: none; border: none; cursor: pointer;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            display: inline-flex; align-items: center; justify-content: center; gap: 6px;
            font-size: 0.88rem; box-shadow: var(--glow-green);
        }
        .btn::after {
            content: ''; position: absolute; top: 0; left: -100%; width: 60%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.45), transparent);
            transform: skewX(-20deg); transition: left 0.5s ease;
        }
        .btn:hover::after { left: 130%; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(57, 255, 20, 0.35); }

        .btn-outline {
            background: rgba(57, 255, 20, 0.06); border: 1px solid var(--neon-green);
            color: var(--neon-green); box-shadow: none;
        }
        .btn-outline:hover { background: var(--neon-green); color: #04060b; box-shadow: var(--glow-green); }

        .btn-danger {
            background: linear-gradient(135deg, var(--accent-red), #ff4d6d);
            color: #fff; box-shadow: 0 4px 15px rgba(255, 7, 58, 0.3);
        }
        .btn-danger:hover { box-shadow: 0 6px 20px rgba(255, 7, 58, 0.5); }

        .form-control {
            width: 100%; padding: 0.8rem 1rem;
            background: rgba(0, 0, 0, 0.25); border: 1px solid var(--card-border);
            color: var(--text-main); border-radius: 10px; outline: none;
            margin-bottom: 1rem; font-size: 0.92rem; transition: all 0.25s ease;
        }
        [data-theme="light"] .form-control { background: rgba(15, 23, 42, 0.03); }
        .form-control:focus {
            border-color: var(--neon-green);
            box-shadow: 0 0 0 3px rgba(57, 255, 20, 0.15);
        }

        .container { max-width: 960px; width: 100%; margin: 2rem auto; padding: 0 1rem; flex: 1; }

        .card {
            background: var(--panel-bg); border: 1px solid var(--card-border);
            border-left: 4px solid var(--neon-purple); border-radius: 14px;
            padding: 1.6rem; margin-bottom: 1.4rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            animation: fadeInUp 0.4s ease both;
            transition: transform 0.3s ease, border-color 0.3s ease;
        }
        .card:hover { border-color: rgba(176, 38, 255, 0.4); border-left-color: var(--neon-green); }

        .reel-card {
            flex: 0 0 150px; background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--card-border); border-top: 3px solid var(--neon-green);
            border-radius: 12px; padding: 10px; text-align: center; transition: all 0.3s ease;
        }
        [data-theme="light"] .reel-card { background: rgba(15, 23, 42, 0.03); }
        .reel-card:hover { transform: translateY(-3px); border-color: var(--neon-yellow); }

        .avatar-ring {
            border-radius: 50%; object-fit: cover; border: 2px solid var(--neon-green);
            box-shadow: 0 0 10px rgba(57, 255, 20, 0.25);
        }

        .theme-select {
            background: rgba(204, 255, 0, 0.08); border: 1px solid var(--neon-yellow);
            color: var(--neon-yellow); padding: 0.38rem 0.65rem; border-radius: 8px;
            cursor: pointer; font-size: 0.78rem; font-weight: 700; outline: none;
        }
        .theme-select option {
            background: var(--panel-solid); color: var(--text-main);
        }

        .post-image {
            max-width: 100%; max-height: 420px; border-radius: 12px;
            border: 1px solid var(--card-border); object-fit: cover; display: block;
        }

        footer {
            background: var(--panel-bg); border-top: 1px solid var(--card-border);
            padding: 2rem 1rem; margin-top: 3rem; text-align: center; backdrop-filter: blur(16px);
        }
        .social-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 0.8rem; margin-top: 0.9rem; }
        .social-chip {
            display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1.1rem;
            background: rgba(0, 0, 0, 0.25); border: 1px solid var(--card-border);
            border-radius: 10px; color: var(--text-main); text-decoration: none;
            font-size: 0.82rem; font-weight: 600; transition: all 0.25s ease;
        }
        [data-theme="light"] .social-chip { background: rgba(15, 23, 42, 0.03); }
        .social-chip svg { width: 18px; height: 18px; fill: currentColor; flex-shrink: 0; }
        .social-chip:hover { border-color: var(--neon-green); color: var(--neon-green); transform: translateY(-2px); }

        .alert-error {
            background: rgba(255, 7, 58, 0.12); border: 1px solid var(--accent-red);
            color: var(--accent-red); padding: 0.75rem 1rem; border-radius: 10px;
            margin-bottom: 1rem; font-size: 0.88rem; font-weight: 600;
        }

        @media screen and (max-width: 1024px) {
            .container { max-width: 92%; padding: 0 0.5rem; }
            nav { padding: 0.8rem 1.2rem; }
            .nav-links { gap: 0.85rem; }
        }

        @media screen and (max-width: 767px) {
            nav { padding: 0.8rem 1rem; }
            .menu-toggle { display: flex; }
            .nav-links {
                position: absolute; top: 100%; left: 0; width: 100%;
                background: var(--panel-solid); border-bottom: 1px solid var(--card-border);
                flex-direction: column; align-items: stretch; padding: 1.2rem;
                gap: 0.9rem; display: none; box-shadow: 0 10px 30px rgba(0,0,0,0.4);
                backdrop-filter: blur(16px);
            }
            .nav-links.active { display: flex; animation: fadeInUp 0.3s ease; }
            .nav-links a:not(.btn) { padding: 0.5rem 0; font-size: 1rem; border-bottom: 1px solid var(--card-border); }

            .card { padding: 1.2rem; }
            .notes-grid, .admin-grid, .publish-grid, form[style*="grid-template-columns"] {
                display: flex !important; flex-direction: column !important;
            }
            .social-grid { flex-direction: column; align-items: stretch; }
            .social-chip { justify-content: center; }
        }
    </style>
    <script>
        const DEFAULT_AVATAR_SVG = "data:image/svg+xml;utf8," + encodeURIComponent(`
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120">
                <rect width="120" height="120" rx="60" fill="#0d1220"/>
                <circle cx="60" cy="46" r="22" fill="none" stroke="#39ff14" stroke-width="5"/>
                <path d="M24 102 C24 78 96 78 96 102" fill="none" stroke="#b026ff" stroke-width="5" stroke-linecap="round"/>
            </svg>
        `);
        function toggleMobileMenu() {
            document.getElementById('navLinks').classList.toggle('active');
        }
        function applyTheme(themeName) {
            const valid = ['dark', 'light', 'slate', 'chalkboard'];
            const chosen = valid.includes(themeName) ? themeName : 'dark';
            document.documentElement.setAttribute('data-theme', chosen);
            localStorage.setItem('nexus_theme', chosen);
            const sel = document.getElementById('themeSelector');
            if (sel) sel.value = chosen;
        }
        const savedTheme = localStorage.getItem('nexus_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        window.addEventListener('DOMContentLoaded', () => {
            const sel = document.getElementById('themeSelector');
            if (sel) sel.value = savedTheme;
        });
    </script>
</head>
<body>
    <nav>
        <a href="{{ url_for('feed') }}" class="brand">STUD<span>4YOU</span></a>
        <button class="menu-toggle" onclick="toggleMobileMenu()" aria-label="Toggle Menu">
            <span></span><span></span><span></span>
        </button>
        <div class="nav-links" id="navLinks">
            {% if session.get('user_id') %}
                <a href="{{ url_for('feed') }}">Feed</a>
                <a href="{{ url_for('notes') }}">PDF Notes</a>
                <a href="{{ url_for('messages_inbox') }}">Messages</a>
                <a href="{{ url_for('notifications_page') }}" style="position:relative;">
                    Alerts
                    {% if unread_notifs_count > 0 %}
                    <span class="badge-count">{{ unread_notifs_count }}</span>
                    {% endif %}
                </a>
                <a href="{{ url_for('search_users') }}">Search</a>
                <a href="{{ url_for('profile', username=session.get('username')) }}">Profile</a>
                {% if session.get('is_admin') %}
                    <a href="{{ url_for('admin_dashboard') }}" style="color: var(--neon-yellow); font-weight: 700;">Admin Panel</a>
                {% endif %}
                <a href="{{ url_for('logout') }}" class="btn btn-outline" style="padding: 0.35rem 0.85rem; font-size: 0.8rem;">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Sign In</a>
                <a href="{{ url_for('register') }}" class="btn" style="padding: 0.4rem 1rem; font-size: 0.82rem;">Register</a>
            {% endif %}
            <select id="themeSelector" class="theme-select" onchange="applyTheme(this.value)" title="Select Education / UI Theme">
                <option value="dark">Dark Neon</option>
                <option value="light">Daylight</option>
                <option value="slate">Academic Slate</option>
                <option value="chalkboard">Campus Chalkboard</option>
            </select>
        </div>
    </nav>

    <div class="container">
        {% block content %}{% endblock %}
    </div>

    <footer>
        <div style="font-size: 0.8rem; color: var(--neon-yellow); font-weight: 700; letter-spacing: 1px;">DEVELOPER CONTACT &amp; SOCIAL PROFILES</div>
        <div class="social-grid">
            <a href="https://instagram.com/shoyabmogal4" target="_blank" rel="noopener noreferrer" class="social-chip">
                <svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/></svg>
                <span>@shoyabmogal4</span>
            </a>
            <a href="https://www.snapchat.com/add/maxiy2006" target="_blank" rel="noopener noreferrer" class="social-chip">
                <svg viewBox="0 0 24 24"><path d="M12.298 2.002c2.723 0 5.155 1.547 6.136 4.015.343.864.551 1.831.579 2.871.02.76-.23 1.503-.708 2.083-.41.5-.956.883-1.571 1.119-.36.138-.663.393-.836.755-.165.346-.226.74-.176 1.13.069.529.411.979.914 1.144 1.135.372 2.191 1.196 2.898 2.316.481.764.717 1.666.671 2.573-.049.957-.425 1.87-1.077 2.576-.64.693-1.493 1.161-2.428 1.332-1.285.234-2.617.234-3.902 0-.935-.171-1.788-.639-2.428-1.332-.652-.706-1.028-1.619-1.077-2.576-.046-.907.19-1.809.671-2.573.707-1.12 1.763-1.944 2.898-2.316.503-.165.845-.615.914-1.144.05-.39-.011-.784-.176-1.13-.173-.362-.476-.617-.836-.755-.615-.236-1.161-.619-1.571-1.119-.478-.58-.728-1.323-.708-2.083.028-1.04.236-2.007.579-2.871.981-2.468 3.413-4.015 6.136-4.015z"/></svg>
                <span>maxiy2006</span>
            </a>
            <a href="mailto:maxiygamer22@gmail.com" class="social-chip">
                <svg viewBox="0 0 24 24"><path d="M12 12.713l-11.985-9.713h23.97l-11.985 9.713zm0 2.574l-12-9.727v15.44h24v-15.44l-12 9.727z"/></svg>
                <span>maxiygamer22@gmail.com</span>
            </a>
            <a href="https://github.com/toxicshoyab" target="_blank" rel="noopener noreferrer" class="social-chip">
                <svg viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                <span>toxicshoyab</span>
            </a>
        </div>
        <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 1rem;">Student Post Management &amp; Student Management System By SHOYAB &amp; NARAYAN</div>
    </footer>
</body>
</html>
'''

LOGIN_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div style="max-width: 410px; margin: 2.5rem auto;" class="card">
    <div style="text-align: center; margin-bottom: 1.3rem;">
        <h2 style="font-weight: 800; font-size: 1.5rem; color: var(--neon-green);">Welcome Back</h2>
        <p style="font-size: 0.85rem; color: var(--text-dim); margin-top: 0.2rem;">Sign in to access your notes, feed, and messages</p>
    </div>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.3rem;">Username</label>
        <input type="text" name="username" class="form-control" placeholder="Enter your username" required autocomplete="off">

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.3rem;">Password</label>
        <input type="password" name="password" class="form-control" placeholder="Enter your password" required>

        <button type="submit" class="btn" style="width: 100%; margin-top: 0.4rem;">Sign In to Portal</button>
    </form>

    <div style="margin-top: 1.2rem; border-top: 1px solid var(--card-border); padding-top: 1.1rem; text-align: center;">
        <a href="{{ url_for('google_oauth_mock') }}" class="btn btn-outline" style="width: 100%;">
            <span>Sign In with Google / Gmail (Students)</span>
        </a>
    </div>

    <p style="margin-top: 1.2rem; text-align: center; font-size: 0.88rem; color: var(--text-dim);">
        New student? <a href="{{ url_for('register') }}" style="color: var(--neon-yellow); text-decoration: none; font-weight: 700;">Create an account</a>
    </p>

    <p style="margin-top: 0.9rem; text-align: center; font-size: 0.72rem; color: var(--text-dim); line-height: 1.4;">
        By signing in, you agree to our <a href="{{ url_for('terms_page') }}" style="color: var(--neon-green); text-decoration: none;">Terms &amp; Conditions</a> and <a href="{{ url_for('privacy_page') }}" style="color: var(--neon-yellow); text-decoration: none;">Privacy Policy</a>.
    </p>
</div>
''')

REGISTER_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div style="max-width: 500px; margin: 1.2rem auto;" class="card">
    <h2 style="margin-bottom: 0.3rem; font-weight: 800; color: var(--neon-yellow);">Create Student Account</h2>
    <p style="font-size: 0.85rem; color: var(--text-dim); margin-bottom: 1.2rem;">Fill in your academic details to join the student network</p>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <form method="POST" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="bot_trap" style="display:none;" autocomplete="off">

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div>
                <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Username</label>
                <input type="text" name="username" class="form-control" placeholder="e.g. rahul_cs" required>
            </div>
            <div>
                <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Gmail / Email</label>
                <input type="email" name="email" class="form-control" placeholder="student@gmail.com" required>
            </div>
        </div>

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Password</label>
        <input type="password" name="password" class="form-control" placeholder="Create a strong password (min 6 chars)" required>

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Institution / College</label>
        <input type="text" name="institution" class="form-control" placeholder="e.g. University of Technology">

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div>
                <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Education Detail</label>
                <input type="text" name="education" class="form-control" placeholder="B.Sc. Computer Science">
            </div>
            <div>
                <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Achievements</label>
                <input type="text" name="achievements" class="form-control" placeholder="Dean Honors, Hackathon Winner">
            </div>
        </div>

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Profile Picture (PNG, JPG, WEBP)</label>
        <input type="file" name="avatar" class="form-control" accept=".png,.jpg,.jpeg,.gif,.webp,image/*">

        <div style="margin: 0.6rem 0 1rem; display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" name="terms" required style="width: 16px; height: 16px; accent-color: var(--neon-green);">
            <label style="font-size: 0.82rem; color: var(--text-dim);">I accept the <a href="{{ url_for('terms_page') }}" style="color: var(--neon-green);">Terms</a> and <a href="{{ url_for('privacy_page') }}" style="color: var(--neon-yellow);">Privacy Policy</a>.</label>
        </div>

        <button type="submit" class="btn" style="width: 100%;">Complete Registration</button>
    </form>
    <p style="margin-top: 1rem; text-align: center; font-size: 0.88rem; color: var(--text-dim);">
        Already registered? <a href="{{ url_for('login') }}" style="color: var(--neon-green); text-decoration: none; font-weight: 700;">Sign In</a>
    </p>
</div>
''')

FEED_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div style="max-width: 720px; margin: auto;">
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}

    <!-- Recent PDF Notes Reel -->
    <div class="card" style="padding: 1.2rem; margin-bottom: 1.4rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
            <h4 style="font-size: 0.82rem; color: var(--neon-yellow); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 800;">Recent Uploaded PDF Notes</h4>
            <a href="{{ url_for('notes') }}" style="font-size: 0.78rem; color: var(--neon-green); text-decoration: none; font-weight: 600;">+ Upload Note</a>
        </div>
        <div style="display: flex; gap: 12px; overflow-x: auto; padding-bottom: 4px;">
            {% for note in recent_notes %}
            <div class="reel-card">
                <div style="font-size: 0.78rem; color: var(--neon-green); font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{ note[2] }}</div>
                <div style="font-size: 0.7rem; color: var(--text-dim); margin: 2px 0;">{{ note[3] }}</div>
                <div style="font-size: 0.65rem; color: var(--neon-purple); font-weight: 600;">@{{ note[7] }}</div>
                <a href="{{ url_for('static', filename='uploads/' + note[5]) }}" target="_blank" rel="noopener noreferrer" class="btn btn-outline" style="padding: 0.2rem 0.4rem; font-size: 0.68rem; margin-top: 6px; width: 100%;">Open PDF</a>
            </div>
            {% else %}
            <div style="font-size: 0.82rem; color: var(--text-dim);">No PDF notes shared yet. Upload one from the PDF Notes tab!</div>
            {% endfor %}
        </div>
    </div>

    <!-- Create Post with Picture & PDF -->
    <div class="card">
        <h3 style="margin-bottom: 0.75rem; font-weight: 700; font-size: 1.05rem; color: var(--neon-green);">Publish Study Post, Picture or PDF</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <textarea name="content" class="form-control" rows="3" placeholder="Ask a question, share diagrams/pictures, attach a lecture PDF, or post an announcement..." required style="margin-bottom: 0.7rem; resize: vertical;"></textarea>

            <div class="publish-grid" style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 10px; align-items: center;">
                <div>
                    <label style="font-size: 0.74rem; color: var(--neon-yellow); font-weight: 700; display: block; margin-bottom: 3px;">Attach Picture (JPG/PNG/WEBP)</label>
                    <input type="file" name="photo_file" class="form-control" accept=".png,.jpg,.jpeg,.gif,.webp,image/*" style="margin-bottom: 0; font-size: 0.78rem; padding: 0.45rem;">
                </div>
                <div>
                    <label style="font-size: 0.74rem; color: var(--neon-green); font-weight: 700; display: block; margin-bottom: 3px;">Attach PDF Document (.pdf)</label>
                    <input type="file" name="pdf_file" class="form-control" accept=".pdf,application/pdf" style="margin-bottom: 0; font-size: 0.78rem; padding: 0.45rem;">
                </div>
                <button type="submit" name="create_post" class="btn" style="align-self: flex-end;">Publish</button>
            </div>
        </form>
    </div>

    <!-- Posts Stream -->
    {% for post in posts %}
    <div class="card" id="post-{{ post[0] }}">
        <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 0.9rem;">
            <img src="{{ url_for('static', filename='uploads/' + (post[6] if post[6] else 'default.png')) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 42px; height: 42px;">
            <div>
                <a href="{{ url_for('profile', username=post[5]) }}" style="color: var(--text-main); text-decoration: none; font-weight: 700; font-size: 1rem;">{{ post[5] }}</a>
                <div style="font-size: 0.72rem; color: var(--text-dim);">{{ post[4] }}</div>
            </div>
        </div>

        <p style="font-size: 0.98rem; line-height: 1.55; margin-bottom: 0.9rem; white-space: pre-line;">{{ post[2] }}</p>

        {% if post[3] %}
        <div style="margin-bottom: 0.9rem;">
            <a href="{{ url_for('static', filename='uploads/' + post[3]) }}" target="_blank" rel="noopener noreferrer">
                <img src="{{ url_for('static', filename='uploads/' + post[3]) }}" onerror="this.style.display='none';" alt="Attached post picture" class="post-image">
            </a>
        </div>
        {% endif %}

        {% if post[10] %}
        <div style="margin-bottom: 0.9rem; background: rgba(0,0,0,0.2); padding: 0.65rem 0.9rem; border-radius: 10px; border: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <span style="font-size: 0.84rem; font-weight: 700; color: var(--neon-yellow);">Attached Study PDF</span>
            <a href="{{ url_for('static', filename='uploads/' + post[10]) }}" target="_blank" rel="noopener noreferrer" class="btn btn-outline" style="padding: 0.3rem 0.85rem; font-size: 0.78rem;">Open / Download PDF</a>
        </div>
        {% endif %}

        <div style="display: flex; gap: 0.7rem; border-top: 1px solid var(--card-border); padding-top: 0.75rem; flex-wrap: wrap;">
            <a href="{{ url_for('toggle_like', post_id=post[0]) }}" class="btn {% if not post[8] %}btn-outline{% endif %}" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">
                &#9829; {{ post[7] }} Likes
            </a>
            <button onclick="navigator.clipboard.writeText(window.location.origin + '/feed#post-{{ post[0] }}'); alert('Post link copied!');" class="btn btn-outline" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">
                Share Link
            </button>
        </div>

        <!-- Comments -->
        <div style="margin-top: 0.9rem; background: rgba(0,0,0,0.2); padding: 0.8rem; border-radius: 10px; border: 1px solid var(--card-border);">
            <div style="font-size: 0.75rem; font-weight: 700; color: var(--neon-yellow); margin-bottom: 0.4rem; text-transform: uppercase;">Comments</div>
            {% for c in post[9] %}
            <div style="font-size: 0.86rem; margin-bottom: 0.4rem;">
                <a href="{{ url_for('profile', username=c[1]) }}" style="color: var(--neon-green); font-weight: 700; text-decoration: none;">{{ c[1] }}:</a> {{ c[2] }}
            </div>
            {% else %}
            <div style="font-size: 0.82rem; color: var(--text-dim); margin-bottom: 0.4rem;">No comments yet. Start the discussion!</div>
            {% endfor %}
            <form action="{{ url_for('add_comment', post_id=post[0]) }}" method="POST" style="display: flex; gap: 6px; margin-top: 0.5rem;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="text" name="comment_content" class="form-control" placeholder="Add a comment..." required style="margin-bottom: 0; padding: 0.45rem 0.75rem; font-size: 0.82rem;">
                <button type="submit" class="btn" style="padding: 0.45rem 0.9rem; font-size: 0.8rem;">Send</button>
            </form>
        </div>
    </div>
    {% endfor %}
</div>
''')

NOTES_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
{% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
<div style="display: grid; grid-template-columns: 1fr 1.7fr; gap: 1.4rem;" class="notes-grid">
    <div class="card" style="height: fit-content;">
        <h3 style="margin-bottom: 0.9rem; font-weight: 800; font-size: 1.1rem; color: var(--neon-green);">Upload PDF Note</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Note Title</label>
            <input type="text" name="title" class="form-control" placeholder="e.g. Data Structures Unit 2" required>

            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Subject Code / Name</label>
            <input type="text" name="subject" class="form-control" placeholder="e.g. CS-204" required>

            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Description</label>
            <textarea name="description" class="form-control" rows="2" placeholder="Key topics covered..." style="resize:vertical;"></textarea>

            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">PDF Document (.pdf)</label>
            <input type="file" name="pdf_file" class="form-control" accept=".pdf,application/pdf" required style="font-size: 0.82rem;">

            <button type="submit" class="btn" style="width: 100%;">Save to Vault</button>
        </form>
    </div>

    <div>
        <h3 style="margin-bottom: 0.9rem; font-weight: 800; font-size: 1.1rem; color: var(--neon-yellow);">Your PDF Notes Vault</h3>
        {% for note in notes %}
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: start; gap: 8px; flex-wrap: wrap;">
                <div>
                    <h4 style="font-weight: 700; font-size: 1.05rem; color: var(--neon-green);">{{ note[2] }}</h4>
                    <span style="color: var(--neon-yellow); font-size: 0.8rem; font-weight: 700;">Subject: {{ note[3] }}</span>
                </div>
                <a href="{{ url_for('static', filename='uploads/' + note[5]) }}" target="_blank" rel="noopener noreferrer" class="btn btn-outline" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">View PDF</a>
            </div>
            <p style="margin-top: 0.5rem; color: var(--text-dim); font-size: 0.88rem;">{{ note[4] }}</p>
            <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.7rem;">Uploaded: {{ note[6] }}</div>
        </div>
        {% else %}
        <div class="card" style="color: var(--text-dim); text-align: center;">You haven't uploaded any PDF notes yet.</div>
        {% endfor %}
    </div>
</div>
''')

PROFILE_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div style="display: flex; gap: 1.8rem; align-items: flex-start; flex-wrap: wrap;">
        <img src="{{ url_for('static', filename='uploads/' + profile[5]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 105px; height: 105px; border-width: 3px;">
        <div style="flex: 1; min-width: 240px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <div>
                    <h2 style="font-weight: 800; font-size: 1.4rem; color: var(--neon-green);">{{ profile[1] }}</h2>
                    <p style="color: var(--neon-yellow); font-size: 0.86rem; font-weight: 600;">{{ profile[7] }}</p>
                </div>
                {% if session.get('user_id') == profile[0] %}
                <a href="{{ url_for('edit_profile') }}" class="btn btn-outline" style="padding: 0.35rem 0.9rem; font-size: 0.8rem;">Edit Profile</a>
                {% endif %}
            </div>

            <p style="margin: 0.6rem 0; font-size: 0.92rem; line-height: 1.5;">{{ profile[6] }}</p>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 0.8rem; font-size: 0.85rem; background: rgba(0,0,0,0.2); padding: 0.8rem; border-radius: 10px; border: 1px solid var(--card-border);">
                <div><strong style="color: var(--neon-green); display: block; margin-bottom: 2px;">Education</strong> {{ profile[8] }}</div>
                <div><strong style="color: var(--neon-yellow); display: block; margin-bottom: 2px;">Achievements</strong> {{ profile[9] }}</div>
            </div>

            <div style="display: flex; gap: 1.5rem; margin-top: 1rem; font-weight: 700; font-size: 0.92rem;">
                <a href="{{ url_for('view_followers', username=profile[1]) }}" style="color: var(--text-main); text-decoration: none;">Followers: <span style="color: var(--neon-green);">{{ followers_count }}</span></a>
                <a href="{{ url_for('view_following', username=profile[1]) }}" style="color: var(--text-main); text-decoration: none;">Following: <span style="color: var(--neon-yellow);">{{ following_count }}</span></a>
            </div>

            {% if session.get('user_id') != profile[0] %}
            <div style="margin-top: 1.2rem; display: flex; gap: 8px;">
                <a href="{{ url_for('toggle_follow', user_id=profile[0]) }}" class="btn {% if is_following %}btn-outline{% endif %}" style="padding: 0.4rem 1.2rem;">
                    {% if is_following %}Unfollow{% else %}Follow{% endif %}
                </a>
                <a href="{{ url_for('chat_room', user_id=profile[0]) }}" class="btn btn-outline" style="padding: 0.4rem 1.2rem;">Message</a>
            </div>
            {% endif %}
        </div>
    </div>
</div>
''')

EDIT_PROFILE_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div style="max-width: 560px; margin: auto;" class="card">
    <h2 style="margin-bottom: 1.1rem; font-weight: 800; color: var(--neon-green);">Edit Profile Details</h2>
    {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
    <form method="POST" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Institution / College</label>
        <input type="text" name="institution" class="form-control" value="{{ profile[7] }}">

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Bio / About Me</label>
        <textarea name="bio" class="form-control" rows="2" style="resize:vertical;">{{ profile[6] }}</textarea>

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Education Detail</label>
        <input type="text" name="education" class="form-control" value="{{ profile[8] }}">

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Achievements &amp; Awards</label>
        <input type="text" name="achievements" class="form-control" value="{{ profile[9] }}">

        <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-dim); display:block; margin-bottom: 0.25rem;">Update Profile Picture</label>
        <input type="file" name="avatar" class="form-control" accept=".png,.jpg,.jpeg,.gif,.webp,image/*" style="font-size: 0.82rem;">

        <div style="display: flex; gap: 8px; margin-top: 0.9rem;">
            <button type="submit" class="btn">Save Changes</button>
            <a href="{{ url_for('profile', username=session.get('username')) }}" class="btn btn-outline">Cancel</a>
        </div>
    </form>
</div>
''')

FOLLOW_LIST_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2 style="margin-bottom: 1.1rem; font-weight: 800; color: var(--neon-yellow);">{{ title }} &bull; {{ username }}</h2>

    <div>
        {% for u in users %}
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--card-border); flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; gap: 10px; align-items: center;">
                <img src="{{ url_for('static', filename='uploads/' + u[5]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 40px; height: 40px;">
                <div>
                    <h4 style="font-weight: 700; font-size: 0.95rem;"><a href="{{ url_for('profile', username=u[1]) }}" style="color: var(--text-main); text-decoration: none;">{{ u[1] }}</a></h4>
                    <span style="font-size: 0.76rem; color: var(--text-dim);">{{ u[7] }}</span>
                </div>
            </div>

            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                <a href="{{ url_for('profile', username=u[1]) }}" class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">Profile</a>
                <a href="{{ url_for('chat_room', user_id=u[0]) }}" class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">Chat</a>
                {% if is_owner and list_type == 'followers' %}
                <a href="{{ url_for('remove_follower', user_id=u[0]) }}" class="btn btn-danger" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;" onclick="return confirm('Remove follower?')">Remove</a>
                {% elif is_owner and list_type == 'following' %}
                <a href="{{ url_for('toggle_follow', user_id=u[0]) }}" class="btn btn-danger" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">Unfollow</a>
                {% endif %}
            </div>
        </div>
        {% else %}
        <p style="color: var(--text-dim); text-align: center; padding: 1.2rem;">No users in this list yet.</p>
        {% endfor %}
    </div>

    <div style="margin-top: 1.2rem;">
        <a href="{{ url_for('profile', username=username) }}" class="btn btn-outline" style="font-size: 0.8rem;">Back to Profile</a>
    </div>
</div>
''')

INBOX_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2 style="margin-bottom: 0.3rem; font-weight: 800; color: var(--neon-green);">Direct Messages</h2>
    <p style="color: var(--text-dim); font-size: 0.86rem; margin-bottom: 1.2rem;">Chat privately with your followers and people you follow.</p>

    <div>
        {% for u in contacts %}
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--card-border);">
            <div style="display: flex; gap: 10px; align-items: center;">
                <img src="{{ url_for('static', filename='uploads/' + u[5]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 40px; height: 40px;">
                <div>
                    <h4 style="font-weight: 700; font-size: 0.95rem;"><a href="{{ url_for('profile', username=u[1]) }}" style="color: var(--text-main); text-decoration: none;">{{ u[1] }}</a></h4>
                    <span style="font-size: 0.76rem; color: var(--text-dim);">{{ u[7] }}</span>
                </div>
            </div>
            <a href="{{ url_for('chat_room', user_id=u[0]) }}" class="btn" style="padding: 0.3rem 0.85rem; font-size: 0.78rem;">Open Chat</a>
        </div>
        {% else %}
        <p style="color: var(--text-dim); text-align: center; padding: 1.2rem;">Follow students from the Search tab to start chatting!</p>
        {% endfor %}
    </div>
</div>
''')

CHAT_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card" style="display: flex; flex-direction: column; height: 480px;">
    <div style="display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--card-border); padding-bottom: 0.9rem; margin-bottom: 0.9rem;">
        <img src="{{ url_for('static', filename='uploads/' + other_user[5]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 38px; height: 38px;">
        <div>
            <h3 style="font-size: 1.05rem; font-weight: 700;"><a href="{{ url_for('profile', username=other_user[1]) }}" style="color: var(--neon-green); text-decoration: none;">{{ other_user[1] }}</a></h3>
            <span style="font-size: 0.72rem; color: var(--text-dim);">{{ other_user[7] }}</span>
        </div>
    </div>

    <div id="chat-box" style="flex: 1; overflow-y: auto; padding-right: 8px; display: flex; flex-direction: column; gap: 8px; margin-bottom: 0.9rem;">
        {% for msg in messages %}
        <div style="max-width: 75%; padding: 0.65rem 0.95rem; border-radius: 10px; animation: fadeInUp 0.25s ease; {% if msg[1] == session['user_id'] %}align-self: flex-end; background: linear-gradient(135deg, var(--neon-green), var(--neon-yellow)); color: #04060b; font-weight: 600;{% else %}align-self: flex-start; background: rgba(0,0,0,0.3); border: 1px solid var(--card-border); color: var(--text-main);{% endif %}">
            <div style="font-size: 0.9rem; word-break: break-word;">{{ msg[3] }}</div>
            <div style="font-size: 0.62rem; opacity: 0.75; margin-top: 3px; text-align: right;">{{ msg[4] }}</div>
        </div>
        {% else %}
        <p style="color: var(--text-dim); text-align: center; margin: auto;">No messages yet. Say hello!</p>
        {% endfor %}
    </div>

    <form method="POST" style="display: flex; gap: 8px;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="content" class="form-control" placeholder="Write your message..." required style="margin-bottom: 0;" autocomplete="off">
        <button type="submit" class="btn" style="white-space: nowrap;">Send</button>
    </form>
</div>
<script>
    const chatBox = document.getElementById('chat-box');
    chatBox.scrollTop = chatBox.scrollHeight;
</script>
''')

NOTIFICATIONS_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.1rem; flex-wrap: wrap; gap: 8px;">
        <h2 style="font-weight: 800; color: var(--neon-green); font-size: 1.3rem;">Notifications &amp; Alerts</h2>
        <a href="{{ url_for('mark_notifications_read') }}" class="btn btn-outline" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">Mark All Read</a>
    </div>

    <div>
        {% for notif in notifications %}
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.75rem; border-bottom: 1px solid var(--card-border); flex-wrap: wrap; gap: 8px; {% if not notif[4] %}background: rgba(57, 255, 20, 0.05); border-left: 3px solid var(--neon-green); border-radius: 8px;{% endif %}">
            <div style="display: flex; gap: 10px; align-items: center;">
                <img src="{{ url_for('static', filename='uploads/' + notif[7]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 38px; height: 38px;">
                <div>
                    <div style="font-size: 0.9rem;">
                        <strong style="color: var(--neon-green);">{{ notif[6] }}</strong>
                        {% if notif[2] == 'followed' %}started following you.
                        {% elif notif[2] == 'liked' %}liked your post.
                        {% elif notif[2] == 'commented' %}commented on your post.
                        {% elif notif[2] == 'messaged' %}sent you a direct message.
                        {% endif %}
                    </div>
                    <span style="font-size: 0.72rem; color: var(--text-dim);">{{ notif[3] }}</span>
                </div>
            </div>

            <div>
                {% if notif[2] in ['liked', 'commented'] and notif[5] %}
                <a href="{{ url_for('feed') }}#post-{{ notif[5] }}" class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">View Post</a>
                {% elif notif[2] == 'followed' %}
                <a href="{{ url_for('profile', username=notif[6]) }}" class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">Profile</a>
                {% elif notif[2] == 'messaged' %}
                <a href="{{ url_for('chat_room', user_id=notif[1]) }}" class="btn btn-outline" style="padding: 0.25rem 0.65rem; font-size: 0.72rem;">Reply</a>
                {% endif %}
            </div>
        </div>
        {% else %}
        <p style="color: var(--text-dim); text-align: center; padding: 1.5rem;">You're all caught up! No notifications yet.</p>
        {% endfor %}
    </div>
</div>
''')

PRIVACY_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2 style="font-weight: 800; color: var(--neon-green); margin-bottom: 0.9rem;">Privacy Policy</h2>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">Welcome to STUD4YOU Portal. This platform is created by Shoyab Mogal and Narayan Kulkarni. Passwords are stored using salted cryptographic hashes rather than plain text.</p>
    <h3 style="color: var(--neon-yellow); font-size: 1rem; margin-top: 0.9rem; margin-bottom: 0.3rem;">1. Information We Collect</h3>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">We store profile details provided during registration and profile updates, including username, email, institution, education details, achievements, uploaded pictures, and study PDFs.</p>
    <h3 style="color: var(--neon-yellow); font-size: 1rem; margin-top: 0.9rem; margin-bottom: 0.3rem;">2. How Information is Used</h3>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">Your data powers student discovery, peer study sharing, and direct messaging within the portal.</p>
    <div style="margin-top: 1.2rem;"><a href="{{ url_for('login') }}" class="btn btn-outline" style="font-size: 0.8rem;">Back to Sign In</a></div>
</div>
''')

TERMS_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2 style="font-weight: 800; color: var(--neon-yellow); margin-bottom: 0.9rem;">Terms and Conditions</h2>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">By creating an account or signing into STUD4YOU Portal, you agree to follow our academic integrity and student conduct guidelines.</p>
    <h3 style="color: var(--neon-green); font-size: 1rem; margin-top: 0.9rem; margin-bottom: 0.3rem;">1. Academic Conduct</h3>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">Students must share helpful, legitimate study notes and pictures and maintain respectful communication across posts, comments, and direct messages.</p>
    <h3 style="color: var(--neon-green); font-size: 1rem; margin-top: 0.9rem; margin-bottom: 0.3rem;">2. Account Security</h3>
    <p style="color: var(--text-dim); line-height: 1.55; margin-bottom: 0.9rem;">You are responsible for safeguarding your login credentials and reporting any unauthorized activity.</p>
    <div style="margin-top: 1.2rem;"><a href="{{ url_for('login') }}" class="btn btn-outline" style="font-size: 0.8rem;">Back to Sign In</a></div>
</div>
''')

SEARCH_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h3 style="margin-bottom: 0.9rem; font-weight: 800; font-size: 1.1rem; color: var(--neon-green);">Search Student Directory</h3>
    <form method="GET" style="display: flex; gap: 8px;">
        <input type="text" name="q" class="form-control" placeholder="Search by username, college, education, achievements..." value="{{ query }}" style="margin-bottom: 0;">
        <button type="submit" class="btn" style="white-space: nowrap;">Search</button>
    </form>
</div>

<div>
    {% for u in results %}
    <div class="card" style="display: flex; justify-content: space-between; align-items: center; padding: 1.1rem; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; gap: 12px; align-items: center;">
            <img src="{{ url_for('static', filename='uploads/' + u[5]) }}" onerror="this.onerror=null;this.src=DEFAULT_AVATAR_SVG;" class="avatar-ring" style="width: 44px; height: 44px;">
            <div>
                <h4 style="font-weight: 700; font-size: 1rem;"><a href="{{ url_for('profile', username=u[1]) }}" style="color: var(--neon-green); text-decoration: none;">{{ u[1] }}</a></h4>
                <div style="font-size: 0.8rem; color: var(--neon-yellow); font-weight: 600;">{{ u[7] }} &bull; {{ u[8] }}</div>
                <div style="font-size: 0.74rem; color: var(--text-dim);">Achievements: {{ u[9] }}</div>
            </div>
        </div>
        <div style="display: flex; gap: 6px;">
            <a href="{{ url_for('profile', username=u[1]) }}" class="btn btn-outline" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">Profile</a>
            <a href="{{ url_for('chat_room', user_id=u[0]) }}" class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.78rem;">Message</a>
        </div>
    </div>
    {% else %}
    {% if query %}
    <div class="card" style="text-align: center; color: var(--text-dim);">No student profiles matched "{{ query }}".</div>
    {% endif %}
    {% endfor %}
</div>
''')

ADMIN_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2 style="font-weight: 800; color: var(--neon-yellow); margin-bottom: 1.3rem; font-size: 1.3rem;">
        Administrator Control Panel (shoyab55555)
    </h2>

    <div style="margin-bottom: 1.5rem; background: rgba(0,0,0,0.2); padding: 1.1rem; border-radius: 12px; border: 1px solid var(--card-border);">
        <h4 style="font-weight: 700; margin-bottom: 0.6rem; color: var(--neon-green);">Add New Student Account</h4>
        <form action="{{ url_for('admin_add_user') }}" method="POST" class="admin-grid" style="display: grid; grid-template-columns: repeat(3, 1fr) auto; gap: 8px;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="text" name="username" class="form-control" placeholder="Username" required style="margin-bottom:0;">
            <input type="email" name="email" class="form-control" placeholder="Email" required style="margin-bottom:0;">
            <input type="password" name="password" class="form-control" placeholder="Password" required style="margin-bottom:0;">
            <button type="submit" class="btn">Add User</button>
        </form>
    </div>

    <div style="margin-bottom: 1.5rem; background: rgba(0,0,0,0.2); padding: 1.1rem; border-radius: 12px; border: 1px solid var(--card-border);">
        <h4 style="font-weight: 700; margin-bottom: 0.6rem; color: var(--neon-yellow);">Search &amp; Filter Users</h4>
        <form method="GET" style="display: flex; gap: 8px; flex-wrap: wrap;">
            <input type="text" name="q" class="form-control" placeholder="Search by username, email, education..." value="{{ search_query }}" style="margin-bottom:0; flex:1; min-width: 200px;">
            <button type="submit" class="btn">Search</button>
            {% if search_query %}
            <a href="{{ url_for('admin_dashboard') }}" class="btn btn-outline" style="white-space: nowrap;">Reset</a>
            {% endif %}
        </form>
    </div>

    <h3 style="font-weight: 700; margin-bottom: 0.9rem; font-size: 1.05rem; color: var(--neon-green);">Registered Users &amp; Profile Database</h3>
    <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 1.8rem; font-size: 0.85rem; min-width: 600px;">
            <thead>
                <tr style="border-bottom: 2px solid var(--card-border); text-align: left; color: var(--neon-yellow);">
                    <th style="padding: 0.6rem;">ID</th>
                    <th>User</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Education &amp; Institution</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for u in users %}
                <tr style="border-bottom: 1px solid var(--card-border);">
                    <td style="padding: 0.7rem 0.6rem;">#{{ u[0] }}</td>
                    <td><a href="{{ url_for('profile', username=u[1]) }}" style="font-weight: 700; color: var(--neon-green); text-decoration: none;">{{ u[1] }}</a></td>
                    <td>{{ u[2] }}</td>
                    <td>{% if u[10] %}<span style="color: var(--neon-yellow); font-weight: 800;">ADMIN</span>{% else %}Student{% endif %}</td>
                    <td style="color: var(--text-dim);">{{ u[8] }} ({{ u[7] }})</td>
                    <td>
                        {% if u[1] != 'shoyab55555' %}
                        <form action="{{ url_for('admin_remove_user', user_id=u[0]) }}" method="POST" style="display:inline;" onsubmit="return confirm('Delete user permanently?')">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                            <button type="submit" class="btn btn-danger" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Delete</button>
                        </form>
                        {% else %}
                        <span style="font-size: 0.72rem; color: var(--neon-yellow); font-weight: 800;">SUPERADMIN</span>
                        {% endif %}
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="6" style="text-align: center; padding: 1.1rem; color: var(--text-dim);">No users found.</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <h3 style="font-weight: 700; margin-bottom: 0.9rem; font-size: 1.05rem; color: var(--neon-yellow);">Real-Time User Activity Stream</h3>
    <div style="max-height: 220px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 0.9rem; border-radius: 10px; border: 1px solid var(--card-border);">
        {% for act in activities %}
        <div style="font-size: 0.82rem; margin-bottom: 0.4rem; font-family: monospace;">
            <span style="color: var(--neon-yellow);">[{{ act[3] }}]</span> <strong style="color: var(--neon-green);">{{ act[1] }}</strong> ({{ act[2] }}): {{ act[0] }}
        </div>
        {% endfor %}
    </div>
</div>
''')


# ================= CONTEXT PROCESSOR =================
@app.context_processor
def inject_globals():
    unread_count = 0
    if 'user_id' in session:
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (session['user_id'],))
            res = cursor.fetchone()
            if res:
                unread_count = res[0]
            conn.close()
        except Exception:
            pass
    return dict(unread_notifs_count=unread_count, csrf_token=get_csrf_token())


# ================= FLASK ROUTES =================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        validate_csrf()
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password, is_admin FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and verify_and_upgrade_password(cursor, user[0], user[2], password):
            conn.commit()
            conn.close()
            session.clear()
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3]
            log_activity(user[0], "Signed In")
            return redirect(url_for('feed'))

        conn.close()
        error = 'Invalid username or password.'
    return render_template_string(LOGIN_HTML, error=error)


@app.route('/privacy-policy')
def privacy_page():
    return render_template_string(PRIVACY_HTML)


@app.route('/terms')
def terms_page():
    return render_template_string(TERMS_HTML)


@app.route('/oauth/google')
def google_oauth_mock():
    email = "student.cadet@gmail.com"
    username = "student_cadet"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_admin FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if not user:
        hashed_pw = generate_password_hash(secrets.token_urlsafe(24))
        cursor.execute('''
            INSERT INTO users (username, email, password, is_admin)
            VALUES (?, ?, ?, 0)
        ''', (username, email, hashed_pw))
        conn.commit()
        cursor.execute('SELECT id, username, is_admin FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

    conn.close()
    if user[1] == 'shoyab55555' or user[2] == 1:
        return redirect(url_for('login'))

    session.clear()
    session['user_id'] = user[0]
    session['username'] = user[1]
    session['is_admin'] = 0
    log_activity(user[0], "Signed In via Google")
    return redirect(url_for('feed'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        validate_csrf()
        if request.form.get('bot_trap'):
            return "Bot activity detected.", 403

        username = request.form['username'].strip()
        email = request.form['email'].strip()
        raw_pw = request.form['password']
        if len(raw_pw) < 6:
            error = 'Password must be at least 6 characters long.'
            return render_template_string(REGISTER_HTML, error=error)

        hashed_pw = generate_password_hash(raw_pw)
        institution = (request.form.get('institution') or '').strip() or 'University of Technology'
        education = (request.form.get('education') or '').strip() or 'B.Sc. Computer Science'
        achievements = (request.form.get('achievements') or '').strip() or 'Active Student Member'

        avatar_filename = 'default.png'
        if 'avatar' in request.files and request.files['avatar'].filename:
            saved_avatar, upload_err = save_validated_upload(request.files['avatar'], ALLOWED_IMAGES)
            if upload_err:
                return render_template_string(REGISTER_HTML, error=upload_err)
            if saved_avatar:
                avatar_filename = saved_avatar

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password, avatar, institution, education, achievements, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            ''', (username, email, hashed_pw, avatar_filename, institution, education, achievements))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            session.clear()
            session['user_id'] = user_id
            session['username'] = username
            session['is_admin'] = 0
            log_activity(user_id, "Registered Account")
            return redirect(url_for('feed'))
        except sqlite3.IntegrityError:
            error = 'Username or email already exists.'

    return render_template_string(REGISTER_HTML, error=error)


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], "Logged out")
    session.clear()
    return redirect(url_for('login'))


def render_feed_page(error=None):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT n.id, n.user_id, n.title, n.subject, n.description, n.filename, n.uploaded_at, u.username
        FROM notes n JOIN users u ON n.user_id = u.id
        ORDER BY n.uploaded_at DESC LIMIT 10
    ''')
    recent_notes = cursor.fetchall()

    cursor.execute('''
        SELECT p.id, p.author_id, p.content, p.media_file, p.created_at, u.username, u.avatar,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) as user_liked,
               p.pdf_file
        FROM posts p
        JOIN users u ON p.author_id = u.id
        ORDER BY p.created_at DESC
    ''', (session['user_id'],))

    raw_posts = cursor.fetchall()
    posts = []
    for rp in raw_posts:
        cursor.execute('SELECT c.id, u.username, c.content FROM comments c JOIN users u ON c.author_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (rp[0],))
        comments = cursor.fetchall()
        # Tuple layout: (id, author_id, content, media_file, created_at, username, avatar, like_count, user_liked, comments, pdf_file)
        posts.append((rp[0], rp[1], rp[2], rp[3], rp[4], rp[5], rp[6], rp[7], rp[8], comments, rp[9]))

    conn.close()
    return render_template_string(FEED_HTML, posts=posts, recent_notes=recent_notes, error=error)


@app.route('/feed', methods=['GET', 'POST'])
def feed():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST' and 'create_post' in request.form:
        validate_csrf()
        content = request.form['content'].strip()
        if not content:
            return render_feed_page(error="Post content cannot be empty.")

        photo_filename = None
        pdf_filename = None

        if 'photo_file' in request.files and request.files['photo_file'].filename:
            saved_photo, photo_err = save_validated_upload(request.files['photo_file'], ALLOWED_IMAGES)
            if photo_err:
                return render_feed_page(error=f"Picture upload failed: {photo_err}")
            photo_filename = saved_photo

        if 'pdf_file' in request.files and request.files['pdf_file'].filename:
            saved_pdf, pdf_err = save_validated_upload(request.files['pdf_file'], ALLOWED_PDFS)
            if pdf_err:
                return render_feed_page(error=f"PDF upload failed: {pdf_err}")
            pdf_filename = saved_pdf

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO posts (author_id, content, media_file, pdf_file) VALUES (?, ?, ?, ?)',
            (session['user_id'], content, photo_filename, pdf_filename)
        )
        conn.commit()
        conn.close()

        attachments = []
        if photo_filename:
            attachments.append("Picture")
        if pdf_filename:
            attachments.append("PDF")
        suffix = f" with {' & '.join(attachments)}" if attachments else ""
        log_activity(session['user_id'], f"Published Post{suffix}")
        return redirect(url_for('feed'))

    return render_feed_page()


@app.route('/post/<int:post_id>/like')
def toggle_like(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT author_id FROM posts WHERE id = ?', (post_id,))
    p_author = cursor.fetchone()

    cursor.execute('SELECT * FROM likes WHERE user_id = ? AND post_id = ?', (session['user_id'], post_id))
    if cursor.fetchone():
        cursor.execute('DELETE FROM likes WHERE user_id = ? AND post_id = ?', (session['user_id'], post_id))
    else:
        cursor.execute('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', (session['user_id'], post_id))
        if p_author:
            create_notification(p_author[0], session['user_id'], 'liked', post_id)

    conn.commit()
    conn.close()
    return redirect(url_for('feed'))


@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    validate_csrf()
    content = request.form['comment_content'].strip()
    if not content:
        return redirect(url_for('feed'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT author_id FROM posts WHERE id = ?', (post_id,))
    p_author = cursor.fetchone()

    cursor.execute('INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)', (post_id, session['user_id'], content))
    if p_author:
        create_notification(p_author[0], session['user_id'], 'commented', post_id)

    conn.commit()
    conn.close()
    return redirect(url_for('feed'))


@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        validate_csrf()
        title = request.form['title'].strip()
        subject = request.form['subject'].strip()
        description = request.form['description'].strip()
        file = request.files.get('pdf_file')

        saved_pdf, pdf_err = save_validated_upload(file, ALLOWED_PDFS)
        if pdf_err:
            error = pdf_err
        elif not saved_pdf:
            error = "Please select a valid PDF file."
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO notes (user_id, title, subject, description, filename) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], title, subject, description, saved_pdf)
            )
            conn.commit()
            conn.close()
            log_activity(session['user_id'], f"Uploaded PDF Note: {title}")
            return redirect(url_for('notes'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, user_id, title, subject, description, filename, uploaded_at FROM notes WHERE user_id = ? ORDER BY uploaded_at DESC', (session['user_id'],))
    notes_list = cursor.fetchall()
    conn.close()
    return render_template_string(NOTES_HTML, notes=notes_list, error=error)


@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, avatar, bio, institution, education, achievements FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        abort(404)

    # Align indices with PROFILE_HTML: (id, username, email, password_unused, raw_unused, avatar, bio, institution, education, achievements)
    profile_data = (row[0], row[1], row[2], '', '', row[3], row[4], row[5], row[6], row[7])

    cursor.execute('SELECT COUNT(*) FROM follows WHERE followed_id = ?', (profile_data[0],))
    followers_count = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (profile_data[0],))
    following_count = cursor.fetchone()[0]

    cursor.execute('SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], profile_data[0]))
    is_following = cursor.fetchone() is not None

    conn.close()
    return render_template_string(PROFILE_HTML, profile=profile_data, followers_count=followers_count, following_count=following_count, is_following=is_following)


@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        validate_csrf()
        bio = request.form['bio'].strip()
        institution = request.form['institution'].strip()
        education = request.form['education'].strip()
        achievements = request.form['achievements'].strip()

        avatar_filename = None
        if 'avatar' in request.files and request.files['avatar'].filename:
            saved_avatar, upload_err = save_validated_upload(request.files['avatar'], ALLOWED_IMAGES)
            if upload_err:
                error = upload_err
            else:
                avatar_filename = saved_avatar

        if not error:
            conn = get_db()
            cursor = conn.cursor()
            if avatar_filename:
                cursor.execute(
                    'UPDATE users SET bio = ?, institution = ?, education = ?, achievements = ?, avatar = ? WHERE id = ?',
                    (bio, institution, education, achievements, avatar_filename, session['user_id'])
                )
            else:
                cursor.execute(
                    'UPDATE users SET bio = ?, institution = ?, education = ?, achievements = ? WHERE id = ?',
                    (bio, institution, education, achievements, session['user_id'])
                )
            conn.commit()
            conn.close()
            log_activity(session['user_id'], "Updated Profile Details")
            return redirect(url_for('profile', username=session['username']))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, avatar, bio, institution, education, achievements FROM users WHERE id = ?', (session['user_id'],))
    row = cursor.fetchone()
    conn.close()
    profile_data = (row[0], row[1], row[2], '', '', row[3], row[4], row[5], row[6], row[7])
    return render_template_string(EDIT_PROFILE_HTML, profile=profile_data, error=error)


@app.route('/profile/<username>/followers')
def view_followers(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        abort(404)
    target_id = target[0]

    cursor.execute('''
        SELECT u.id, u.username, u.email, '', '', u.avatar, u.bio, u.institution
        FROM follows f JOIN users u ON f.follower_id = u.id WHERE f.followed_id = ?
    ''', (target_id,))
    followers = cursor.fetchall()
    conn.close()

    is_owner = (session['user_id'] == target_id)
    return render_template_string(FOLLOW_LIST_HTML, users=followers, username=username, title="Followers", list_type="followers", is_owner=is_owner)


@app.route('/profile/<username>/following')
def view_following(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        abort(404)
    target_id = target[0]

    cursor.execute('''
        SELECT u.id, u.username, u.email, '', '', u.avatar, u.bio, u.institution
        FROM follows f JOIN users u ON f.followed_id = u.id WHERE f.follower_id = ?
    ''', (target_id,))
    following = cursor.fetchall()
    conn.close()

    is_owner = (session['user_id'] == target_id)
    return render_template_string(FOLLOW_LIST_HTML, users=following, username=username, title="Following", list_type="following", is_owner=is_owner)


@app.route('/profile/remove-follower/<int:user_id>')
def remove_follower(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', (user_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('view_followers', username=session['username']))


@app.route('/profile/<int:user_id>/follow')
def toggle_follow(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return redirect(url_for('feed'))

    cursor.execute('SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], user_id))
    if cursor.fetchone():
        cursor.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', (session['user_id'], user_id))
    else:
        cursor.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)', (session['user_id'], user_id))
        create_notification(user_id, session['user_id'], 'followed')

    conn.commit()
    conn.close()
    return redirect(url_for('profile', username=target[0]))


@app.route('/messages')
def messages_inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT u.id, u.username, u.email, '', '', u.avatar, u.bio, u.institution
        FROM users u
        JOIN follows f ON (f.follower_id = u.id AND f.followed_id = ?) OR (f.followed_id = u.id AND f.follower_id = ?)
        WHERE u.id != ?
    ''', (session['user_id'], session['user_id'], session['user_id']))
    contacts = cursor.fetchall()
    conn.close()
    return render_template_string(INBOX_HTML, contacts=contacts)


@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
def chat_room(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, \'\', \'\', avatar, bio, institution FROM users WHERE id = ?', (user_id,))
    other_user = cursor.fetchone()
    if not other_user:
        conn.close()
        abort(404)

    if request.method == 'POST':
        validate_csrf()
        content = request.form['content'].strip()
        if content:
            cursor.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                           (session['user_id'], user_id, content))
            conn.commit()
            create_notification(user_id, session['user_id'], 'messaged')
        conn.close()
        return redirect(url_for('chat_room', user_id=user_id))

    cursor.execute('''
        SELECT id, sender_id, receiver_id, content, timestamp
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (session['user_id'], user_id, user_id, session['user_id']))
    messages = cursor.fetchall()
    conn.close()
    return render_template_string(CHAT_HTML, other_user=other_user, messages=messages)


@app.route('/notifications')
def notifications_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT n.id, n.actor_id, n.verb, n.timestamp, n.is_read, n.target_id, u.username, u.avatar
        FROM notifications n
        JOIN users u ON n.actor_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.timestamp DESC
    ''', (session['user_id'],))
    notifications = cursor.fetchall()
    conn.close()
    return render_template_string(NOTIFICATIONS_HTML, notifications=notifications)


@app.route('/notifications/mark-read')
def mark_notifications_read():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return redirect(url_for('notifications_page'))


@app.route('/search')
def search_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    query = request.args.get('q', '').strip()
    results = []
    if query:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, '', '', avatar, bio, institution, education, achievements
            FROM users
            WHERE username LIKE ? OR institution LIKE ? OR education LIKE ? OR achievements LIKE ?
        ''', (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
        results = cursor.fetchall()
        conn.close()
    return render_template_string(SEARCH_HTML, results=results, query=query)


@app.route('/admin-panel')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('feed'))

    search_query = request.args.get('q', '').strip()
    conn = get_db()
    cursor = conn.cursor()

    if search_query:
        cursor.execute('''
            SELECT id, username, email, '', '', avatar, bio, institution, education, achievements, is_admin
            FROM users WHERE username LIKE ? OR email LIKE ? OR education LIKE ?
        ''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute('SELECT id, username, email, \'\', \'\', avatar, bio, institution, education, achievements, is_admin FROM users')
    users = cursor.fetchall()

    cursor.execute('''
        SELECT a.action, u.username, a.ip_address, a.timestamp
        FROM activities a JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT 50
    ''')
    activities = cursor.fetchall()
    conn.close()
    return render_template_string(ADMIN_HTML, users=users, activities=activities, search_query=search_query)


@app.route('/admin-panel/remove/<int:user_id>', methods=['POST'])
def admin_remove_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('feed'))
    validate_csrf()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    u = cursor.fetchone()
    if u and u[0] != 'shoyab55555':
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin-panel/add', methods=['POST'])
def admin_add_user():
    if not session.get('is_admin'):
        return redirect(url_for('feed'))
    validate_csrf()
    username = request.form['username'].strip()
    email = request.form['email'].strip()
    raw_pw = request.form['password']
    hashed_pw = generate_password_hash(raw_pw)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 0)',
                       (username, email, hashed_pw))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, port=5000)