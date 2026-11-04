"""Meko Atelier: deliberately vulnerable, isolated training shop. No OS execution."""
import argparse
import base64
import functools
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import threading

from flask import Flask, abort, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from rounds import current_round

TASKS = ('sqli', 'idor', 'upload', 'jwt', 'backup')
ROOT = Path(__file__).resolve().parent


def db(path):
    con = sqlite3.connect(path, timeout=15)
    con.row_factory = sqlite3.Row
    return con


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def token(secret, claims):
    body = b64(b'{"alg":"HS256","typ":"JWT"}') + '.' + b64(json.dumps(claims).encode())
    return body + '.' + b64(hmac.digest(secret.encode(), body.encode(), 'sha256'))


def claims_for(value, secret, patched):
    try:
        head, payload, sig = value.split('.')
        header = json.loads(base64.urlsafe_b64decode(head + '=' * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        if not isinstance(header, dict) or not isinstance(claims, dict):
            return {}
        # CHALLENGE JWT: the verifier trusts the client-controlled algorithm.
        if header.get('alg') == 'none' and not patched:
            valid = sig == ''
        else:
            expected = b64(hmac.digest(secret.encode(), (head + '.' + payload).encode(), 'sha256'))
            valid = header.get('alg') == 'HS256' and hmac.compare_digest(expected, sig)
        if valid and isinstance(claims.get('exp'), (int, float)) and claims['exp'] > time.time():
            return claims
    except (ValueError, TypeError, UnicodeError):
        pass
    return {}


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(DATA_DIR=os.getenv('SHOP_DATA', str(ROOT / 'data')),
                      TEAM_ID=os.getenv('TEAM_ID', 'team1'), MAX_CONTENT_LENGTH=1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
    app.config.update(config or {})
    try:
        interval = int(app.config.get('TICK_SECONDS', os.getenv('FASHION_TICK_SECONDS', '120')))
        if interval < 1:
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise ValueError('TICK_SECONDS must be a positive integer') from exc
    clock = app.config.get('CLOCK', time.time)
    data = Path(app.config['DATA_DIR']).resolve()
    data.mkdir(parents=True, exist_ok=True)
    state_file = data / 'state.json'
    if not state_file.exists():
        state_file.write_text(json.dumps({'team': app.config['TEAM_ID'], 'session_secret': secrets.token_hex(32),
            'jwt_secret': secrets.token_hex(32), 'flags': {t: 'FLAG{' + secrets.token_hex(16) + '}' for t in TASKS}}), encoding='utf-8')
        state_file.chmod(0o600)
    state = json.loads(state_file.read_text(encoding='utf-8'))
    if state['team'] != app.config['TEAM_ID']:
        raise ValueError('DATA_DIR belongs to another team; use a separate directory per team')
    app.secret_key = state['session_secret']
    app.config['FLAGS'] = state['flags']
    patch_file = data / 'patches.json'
    patches = json.loads(patch_file.read_text(encoding='utf-8')) if patch_file.exists() else {}
    app.config.setdefault('PATCHED', {t: bool(patches.get(t, False)) for t in TASKS})
    flags = state['flags']
    auth_db, catalog_db = data / 'customers.db', data / 'catalog.db'
    with db(auth_db) as con:
        con.execute('CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, address TEXT, note TEXT)')
        con.execute('INSERT OR IGNORE INTO customers(username,password,name,email,address,note) VALUES(?,?,?,?,?,?)',
                    ('linh-vip', generate_password_hash(secrets.token_urlsafe(24)), 'Linh Nguyễn',
                     'linh@example.test', '24 Phố Mẫu, Hà Nội (dữ liệu giả)', flags['idor']))
    with db(catalog_db) as con:
        con.executescript('CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT,price INTEGER,image TEXT); CREATE TABLE IF NOT EXISTS supplier_notes(secret TEXT);')
        if not con.execute('SELECT 1 FROM products').fetchone():
            con.executemany('INSERT INTO products VALUES(?,?,?,?)', [
                (1, 'Essential cotton shirt', 349000, 'tee.svg'),
                (2, 'Everyday linen jacket', 799000, 'jacket.svg'),
                (3, 'City pleated skirt', 459000, 'skirt.svg'),
                (4, 'Weekend knit sweater', 549000, 'knit.svg')])
            con.execute('INSERT INTO supplier_notes VALUES(?)', (flags['sqli'],))
    for folder in ('studio/public', 'studio/private', 'studio/manifests', 'backup'):
        (data / folder).mkdir(parents=True, exist_ok=True)
    # Remove legacy static exports; current synthetic documents are rendered per tick.
    for legacy in ('studio/private/design-brief.txt', 'backup/shop.sql.bak'):
        (data / legacy).unlink(missing_ok=True)
    app.config['FLAGS'] = current_round(auth_db, catalog_db, flags, clock(), interval)['flags']
    round_lock = threading.RLock()

    @app.before_request
    def load_round():
        # One Waitress process, multiple threads: no response crosses a rotation.
        round_lock.acquire()
        g.round_locked = True
        g.collection = current_round(auth_db, catalog_db, flags, clock(), interval)
        app.config['FLAGS'] = g.collection['flags']

    @app.teardown_request
    def release_round(error):
        if g.pop('round_locked', False):
            round_lock.release()

    @app.after_request
    def no_stale_documents(response):
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/api/collection')
    def collection():
        return {k: g.collection[k] for k in ('tick', 'locators')}

    def authenticated(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('uid'):
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapped

    def page(title, **kwargs):
        return render_template('shop.html', title=title, team=app.config['TEAM_ID'],
                               collection=g.collection, **kwargs)

    @app.get('/health')
    def health():
        with db(catalog_db) as con:
            con.execute('SELECT 1 FROM products').fetchone()
        return {'status': 'ok', 'team': app.config['TEAM_ID']}

    @app.get('/')
    def home():
        with db(catalog_db) as con:
            products = con.execute('SELECT * FROM products').fetchall()
        return page('Trang chủ', products=products, hero=True)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'GET':
            return page('Đăng ký', mode='register')
        username, password = request.form.get('username', ''), request.form.get('password', '')
        if not re.fullmatch(r'[a-zA-Z0-9_-]{3,32}', username) or not 10 <= len(password) <= 128:
            return page('Đăng ký', mode='register', error='Tên 3–32 ký tự; mật khẩu 10–128 ký tự.'), 400
        try:
            with db(auth_db) as con:
                next_id = con.execute("SELECT COALESCE(MAX(id),1)+1 FROM customers WHERE username != 'linh-vip'").fetchone()[0]
                # Reserve high IDs for rotating synthetic profiles.
                if next_id >= 3000:
                    abort(409)
                con.execute('INSERT INTO customers(id,username,password,name,email,address,note) VALUES(?,?,?,?,?,?,?)',
                    (next_id, username, generate_password_hash(password), request.form.get('name', username)[:80],
                     request.form.get('email', '')[:120], 'Chưa cập nhật', 'Khách hàng mới'))
        except sqlite3.IntegrityError:
            return page('Đăng ký', mode='register', error='Tên tài khoản đã tồn tại.'), 409
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return page('Đăng nhập', mode='login')
        with db(auth_db) as con:
            user = con.execute('SELECT * FROM customers WHERE username=?', (request.form.get('username', ''),)).fetchone()
        if not user or not check_password_hash(user['password'], request.form.get('password', '')):
            return page('Đăng nhập', mode='login', error='Sai tài khoản hoặc mật khẩu.'), 401
        session.clear()
        session['uid'], session['name'] = user['id'], user['name']
        response = redirect(url_for('home'))
        response.set_cookie('fashion_jwt', token(state['jwt_secret'], {'sub': str(user['id']), 'role': 'customer', 'exp': int(time.time()) + 3600}), httponly=True, samesite='Lax')
        return response

    @app.post('/logout')
    def logout():
        session.clear()
        response = redirect(url_for('home'))
        response.delete_cookie('fashion_jwt')
        return response

    @app.get('/search')
    @authenticated
    def search():
        q = request.args.get('q', '')[:300]
        try:
            with db(catalog_db) as con:
                if app.config['PATCHED']['sqli']:
                    products = con.execute('SELECT id,name,price,image FROM products WHERE name LIKE ?', ('%' + q + '%',)).fetchall()
                else:
                    # CHALLENGE SQLi: catalog only, no customer/session tables here.
                    products = con.execute("SELECT id,name,price,image FROM products WHERE name LIKE '%" + q + "%'").fetchall()
        except sqlite3.Error:
            return page('Tìm kiếm', products=[], q=q, error='Truy vấn sản phẩm không hợp lệ.'), 400
        return page('Tìm kiếm', products=products, q=q)

    @app.get('/profile')
    @authenticated
    def my_profile():
        return redirect(url_for('profile', uid=session['uid']))

    @app.get('/profile/<int:uid>')
    @authenticated
    def profile(uid):
        # CHALLENGE IDOR: authentication without object ownership authorization.
        if app.config['PATCHED']['idor'] and uid != session['uid']:
            abort(403)
        with db(auth_db) as con:
            customer = con.execute('SELECT id,name,email,address,note FROM customers WHERE id=?', (uid,)).fetchone()
        if not customer:
            abort(404)
        return page('Hồ sơ khách hàng', customer=customer)

    @app.route('/studio', methods=['GET', 'POST'])
    @authenticated
    def studio():
        if request.method == 'GET':
            return page('Đặt in áo', mode='studio')
        upload = request.files.get('file')
        if not upload or not upload.filename:
            abort(400)
        ext = Path(upload.filename).suffix.lower()
        allowed = ('.png', '.jpg', '.jpeg') if app.config['PATCHED']['upload'] else ('.png', '.jpg', '.jpeg', '.json')
        if ext not in allowed:
            abort(400)
        content = upload.read()
        if ext != '.json' and not (content.startswith(b'\x89PNG\r\n\x1a\n') or content.startswith(b'\xff\xd8\xff')):
            abort(400)
        key = secrets.token_hex(12) + ext
        folder = 'manifests' if ext == '.json' else 'public'
        (data / 'studio' / folder / key).write_bytes(content)
        return redirect(url_for('preview', key=key))

    @app.get('/studio/preview/<key>')
    @authenticated
    def preview(key):
        if not re.fullmatch(r'[a-f0-9]{24}\.(png|jpg|jpeg|json)', key):
            abort(404)
        if key.endswith('.json'):
            if app.config['PATCHED']['upload']:
                abort(403)
            try:
                manifest = json.loads((data / 'studio/manifests' / key).read_text(encoding='utf-8'))
                # CHALLENGE UPLOAD: preview_path escapes public, exposing private brief.
                target = (data / 'studio/public' / manifest['preview_path']).resolve()
                current_brief = (data / 'studio/public' / g.collection['locators']['upload']).resolve()
                if target == current_brief:
                    return page('Xem trước mẫu in', preview_text='Bản thiết kế mùa mới\n' + g.collection['flags']['upload'])
                # Containment guard confines the exercise to studio synthetic files.
                if not target.is_relative_to(data / 'studio') or not target.is_file():
                    abort(400)
                return page('Xem trước mẫu in', preview_text=target.read_text(encoding='utf-8'))
            except (ValueError, TypeError, KeyError, OSError):
                abort(400)
        target = data / 'studio/public' / key
        if not target.is_file():
            abort(404)
        return send_file(target, mimetype='image/png' if key.endswith('.png') else 'image/jpeg')

    @app.get('/vip')
    @authenticated
    def vip():
        claims = claims_for(request.cookies.get('fashion_jwt', ''), state['jwt_secret'], app.config['PATCHED']['jwt'])
        if claims.get('role') != 'vip':
            return page('Ưu đãi VIP', mode='vip', error='Ưu đãi này dành cho hội viên VIP.'), 403
        offer = request.args.get('offer', 'welcome')
        if offer != g.collection['locators']['jwt']:
            abort(404)
        return page('Ưu đãi VIP', vip_code=g.collection['flags']['jwt'])

    @app.get('/robots.txt')
    def robots():
        return 'User-agent: *\nDisallow: ' + g.collection['locators']['backup'] + '\n', 200, {'Content-Type': 'text/plain'}

    @app.get('/backup/<filename>')
    def leaked_backup(filename):
        # CHALLENGE BACKUP: legacy export was accidentally published.
        if app.config['PATCHED']['backup'] or '/backup/' + filename != g.collection['locators']['backup']:
            abort(404)
        return "-- Synthetic export\nINSERT INTO vouchers VALUES ('" + g.collection['flags']['backup'] + "');\n", 200, {'Content-Type': 'text/plain'}

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=False)
