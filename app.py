import os
import json
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, redirect, url_for, flash,
                   request, session, send_file, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user, UserMixin)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from crypto_utils import (generate_rsa_keypair, sign_file_data,
                          verify_file_signature, serialize_public_key,
                          serialize_private_key_encrypted, load_private_key,
                          get_key_fingerprint, generate_certificate,
                          encrypt_message, decrypt_message)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production-xyz')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cryptosign.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['KEYSTORE_FOLDER'] = os.path.join(os.path.dirname(__file__), 'keystores')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['KEYSTORE_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  default='user')   
    _is_active    = db.Column('is_active', db.Boolean, default=True)
    
    blocked_until = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    
    sec_q1        = db.Column(db.String(200), nullable=False)
    sec_a1_hash   = db.Column(db.String(256), nullable=False)
    sec_q2        = db.Column(db.String(200), nullable=False)
    sec_a2_hash   = db.Column(db.String(256), nullable=False)
    sec_q3        = db.Column(db.String(200), nullable=False, server_default='')
    sec_a3_hash   = db.Column(db.String(256), nullable=False, server_default='')
    
    keypairs      = db.relationship('KeyPair',    backref='owner',  lazy=True, cascade='all, delete-orphan')
    signed_files  = db.relationship('SignedFile', backref='signer', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_security_answers(self, a1, a2, a3=''):
        self.sec_a1_hash = generate_password_hash(a1.strip().lower())
        self.sec_a2_hash = generate_password_hash(a2.strip().lower())
        self.sec_a3_hash = generate_password_hash(a3.strip().lower()) if a3.strip() else ''

    def check_security_answers(self, a1, a2, a3=''):
        ok1 = check_password_hash(self.sec_a1_hash, a1.strip().lower())
        ok2 = check_password_hash(self.sec_a2_hash, a2.strip().lower())
        ok3 = (not self.sec_a3_hash) or check_password_hash(self.sec_a3_hash, a3.strip().lower())
        return ok1 and ok2 and ok3

    @property
    def is_admin(self):
        return self.role == 'admin'

    
    @property
    def is_active(self):
        return bool(self._is_active)

    @is_active.setter
    def is_active(self, value):
        self._is_active = value

    @property
    def is_blocked(self):
        """Returns True if the user is currently in a timed block."""
        if self.blocked_until and self.blocked_until > datetime.utcnow():
            return True
        return False

    @property
    def block_remaining(self):
        """Human-readable time remaining on block."""
        if not self.is_blocked:
            return None
        diff = self.blocked_until - datetime.utcnow()
        total = int(diff.total_seconds())
        h, rem = divmod(total, 3600)
        m, s   = divmod(rem, 60)
        if h:
            return f"{h}h {m}m"
        elif m:
            return f"{m}m {s}s"
        return f"{s}s"

class KeyPair(db.Model):
    __tablename__ = 'keypairs'
    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_name            = db.Column(db.String(100), nullable=False)
    public_key_pem      = db.Column(db.Text, nullable=False)
    encrypted_priv_path = db.Column(db.String(300), nullable=False)
    fingerprint         = db.Column(db.String(64),  nullable=False)
    key_size            = db.Column(db.Integer, default=2048)
    is_revoked          = db.Column(db.Boolean, default=False)
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)
    revoked_at          = db.Column(db.DateTime, nullable=True)
    certificate_pem     = db.Column(db.Text, nullable=True)

class SignedFile(db.Model):
    __tablename__ = 'signed_files'
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_id        = db.Column(db.Integer, db.ForeignKey('keypairs.id'), nullable=False)
    filename      = db.Column(db.String(200), nullable=False)
    file_hash     = db.Column(db.String(64),  nullable=False)
    signature_b64 = db.Column(db.Text,        nullable=False)
    signed_at     = db.Column(db.DateTime,    default=datetime.utcnow)
    key           = db.relationship('KeyPair')

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username   = db.Column(db.String(80))
    action     = db.Column(db.String(100), nullable=False)
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helpers
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your primary school?",
    "What was the make of your first car?",
    "What is the name of your oldest sibling?",
    "What street did you grow up on?",
    "What is your childhood nickname?",
    "What is the name of your favourite teacher?",
]

# Default admin credentials - created automatically on first run
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin6217'
ADMIN_EMAIL    = 'admin@cryptosign.local'

def log_action(action, details='', user=None):
    entry = AuditLog(
        user_id    = user.id if user else (current_user.id if current_user.is_authenticated else None),
        username   = user.username if user else (current_user.username if current_user.is_authenticated else 'anonymous'),
        action     = action,
        details    = details,
        ip_address = request.remote_addr,
    )
    db.session.add(entry)
    db.session.commit()

def admin_required(f):
    """Decorator - only allows admin users. Redirects others to dashboard with message."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            # Do NOT reveal the admin panel exists - just redirect silently
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def user_view_required(f):
    """Decorator for user-facing routes. Requires real authenticated login.
    Admins are sent to admin panel UNLESS they toggled to user view."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_active:
            logout_user()
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if current_user.is_admin and not session.get('admin_user_view'):
            return redirect(url_for('admin_index'))
        return f(*args, **kwargs)
    return decorated

def _admin_user_count():
    return User.query.count()

# Auth Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        sec_q1   = request.form.get('sec_q1', '')
        sec_a1   = request.form.get('sec_a1', '').strip()
        sec_q2   = request.form.get('sec_q2', '')
        sec_a2   = request.form.get('sec_a2', '').strip()
        sec_q3   = request.form.get('sec_q3', '')
        sec_a3   = request.form.get('sec_a3', '').strip()

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if username.lower() == 'admin':
            errors.append('That username is reserved.')
        if '@' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if not sec_a1 or not sec_a2 or not sec_a3:
            errors.append('All three security answers are required.')
        if sec_q1 == sec_q2 or sec_q1 == sec_q3 or sec_q2 == sec_q3:
            errors.append('Please choose three different security questions.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html', questions=SECURITY_QUESTIONS,
                                   form_data=request.form)

        user = User(username=username, email=email,
                    sec_q1=sec_q1, sec_q2=sec_q2, sec_q3=sec_q3,
                    role='user')
        user.set_password(password)
        user.set_security_answers(sec_a1, sec_a2, sec_a3)
        db.session.add(user)
        db.session.commit()

        log_action('REGISTER', f'New user registered: {username}', user=user)
        flash(f'Account created! Welcome, {username}.', 'success')
        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('register.html', questions=SECURITY_QUESTIONS, form_data={})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        # Only allow non-empty credentials
        if not username or not password:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        # Always run check_password (even on None user) to prevent timing attacks
        password_ok = user.check_password(password) if user else False

        if user and password_ok:
            if not user.is_active:
                flash('Your account has been deactivated. Contact an administrator.', 'danger')
                return render_template('login.html')
            if user.is_blocked:
                flash(f'Your account is temporarily blocked for {user.block_remaining}. Try again later.', 'danger')
                return render_template('login.html')
            login_user(user, remember=remember)
            log_action('LOGIN', 'Successful login')
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            # Validate next_page to prevent open redirect
            if next_page and not next_page.startswith('/'):
                next_page = None
            if user.is_admin:
                return redirect(next_page or url_for('admin_index'))
            return redirect(next_page or url_for('dashboard'))
        else:
            log_action('LOGIN_FAIL', f'Failed login attempt for: {username}')
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action('LOGOUT', 'User logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User.query.filter_by(email=username.lower()).first()
        if user:
            session['reset_user_id'] = user.id
            return redirect(url_for('security_questions'))
        else:
            flash('No account found with that username or email.', 'danger')
    return render_template('forgot_password.html')

@app.route('/security-questions', methods=['GET', 'POST'])
def security_questions():
    user_id = session.get('reset_user_id')
    if not user_id:
        return redirect(url_for('forgot_password'))

    user = User.query.get(user_id)
    if not user:
        session.pop('reset_user_id', None)
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        a1 = request.form.get('sec_a1', '')
        a2 = request.form.get('sec_a2', '')
        a3 = request.form.get('sec_a3', '')
        if user.check_security_answers(a1, a2, a3):
            session['can_reset_id'] = user.id
            session.pop('reset_user_id', None)
            return redirect(url_for('reset_password'))
        else:
            flash('Incorrect answers. Please try again.', 'danger')

    return render_template('security_questions.html',
                           username=user.username,
                           q1=user.sec_q1, q2=user.sec_q2, q3=user.sec_q3)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_id = session.get('can_reset_id')
    if not user_id:
        return redirect(url_for('forgot_password'))
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')
        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif new_password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()
            session.pop('can_reset_id', None)
            log_action('PASSWORD_RESET', 'Password reset via security questions', user=user)
            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', username=user.username)

# Toggle admin between admin panel and user view
@app.route('/admin/toggle-user-view')
@login_required
def toggle_user_view():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    if session.get('admin_user_view'):
        session.pop('admin_user_view', None)
        return redirect(url_for('admin_index'))
    else:
        session['admin_user_view'] = True
        return redirect(url_for('dashboard'))

# User Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Admins go to admin panel unless they toggled user view
    if current_user.is_admin and not session.get('admin_user_view'):
        return redirect(url_for('admin_index'))
    total_keys  = KeyPair.query.filter_by(user_id=current_user.id).count()
    active_keys = KeyPair.query.filter_by(user_id=current_user.id, is_revoked=False).count()
    total_sigs  = SignedFile.query.filter_by(user_id=current_user.id).count()
    recent_sigs = (SignedFile.query
                   .filter_by(user_id=current_user.id)
                   .order_by(SignedFile.signed_at.desc())
                   .limit(5).all())
    stats = dict(total_keys=total_keys, active_keys=active_keys, total_sigs=total_sigs)
    return render_template('dashboard.html', stats=stats, recent_sigs=recent_sigs)

# Key Management
@app.route('/keys', methods=['GET', 'POST'])
@user_view_required
def manage_keys():
    if request.method == 'POST':
        key_name     = request.form.get('key_name', 'My Key').strip()
        key_password = request.form.get('key_password', '')
        key_size     = int(request.form.get('key_size', 2048))

        if not key_password or len(key_password) < 6:
            flash('Key password must be at least 6 characters.', 'danger')
            return redirect(url_for('manage_keys'))

        private_key, public_key = generate_rsa_keypair(key_size)
        pub_pem     = serialize_public_key(public_key)
        fingerprint = get_key_fingerprint(public_key)

        priv_filename = f"priv_{current_user.id}_{int(datetime.utcnow().timestamp())}.pem"
        priv_path     = os.path.join(app.config['KEYSTORE_FOLDER'], priv_filename)
        with open(priv_path, 'wb') as f:
            f.write(serialize_private_key_encrypted(private_key, key_password))

        cert_pem = generate_certificate(private_key, public_key, current_user.username)

        kp = KeyPair(
            user_id=current_user.id, key_name=key_name,
            public_key_pem=pub_pem.decode(), encrypted_priv_path=priv_path,
            fingerprint=fingerprint, key_size=key_size,
            certificate_pem=cert_pem.decode(),
        )
        db.session.add(kp)
        db.session.commit()

        log_action('KEY_GENERATE', f'Generated {key_size}-bit RSA key: {key_name}')
        flash(f'Key pair "{key_name}" generated successfully!', 'success')
        return redirect(url_for('manage_keys'))

    keypairs = (KeyPair.query.filter_by(user_id=current_user.id)
                .order_by(KeyPair.created_at.desc()).all())
    return render_template('manage_keys.html', keypairs=keypairs)

@app.route('/keys/<int:key_id>/revoke', methods=['POST'])
@user_view_required
def revoke_key(key_id):
    kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    kp.is_revoked = True
    kp.revoked_at = datetime.utcnow()
    db.session.commit()
    log_action('KEY_REVOKE', f'Revoked key: {kp.key_name}')
    flash(f'Key "{kp.key_name}" has been revoked.', 'warning')
    return redirect(url_for('manage_keys'))

@app.route('/keys/<int:key_id>/download-public')
@user_view_required
def download_public_key(key_id):
    kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    from io import BytesIO
    buf = BytesIO(kp.public_key_pem.encode())
    log_action('KEY_DOWNLOAD', f'Downloaded public key: {kp.key_name}')
    return send_file(buf, as_attachment=True,
                     download_name=f'{kp.key_name.replace(" ", "_")}_public.pem',
                     mimetype='application/x-pem-file')

@app.route('/keys/<int:key_id>/download-cert')
@user_view_required
def download_certificate(key_id):
    kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    if not kp.certificate_pem:
        flash('No certificate for this key.', 'warning')
        return redirect(url_for('manage_keys'))
    from io import BytesIO
    buf = BytesIO(kp.certificate_pem.encode())
    return send_file(buf, as_attachment=True,
                     download_name=f'{kp.key_name.replace(" ", "_")}_cert.pem',
                     mimetype='application/x-pem-file')

# Sign File
@app.route('/sign', methods=['GET', 'POST'])
@user_view_required
def sign_file():
    active_keys = KeyPair.query.filter_by(user_id=current_user.id, is_revoked=False).all()

    if request.method == 'POST':
        key_id       = request.form.get('key_id')
        key_password = request.form.get('key_password', '')
        file         = request.files.get('file')

        if not file or file.filename == '':
            flash('Please select a file to sign.', 'danger')
            return render_template('sign_file.html', keys=active_keys)
        if not key_id:
            flash('Please select a key.', 'danger')
            return render_template('sign_file.html', keys=active_keys)

        kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id, is_revoked=False).first()
        if not kp:
            flash('Key not found or revoked.', 'danger')
            return render_template('sign_file.html', keys=active_keys)

        file_data = file.read()
        file_hash = hashlib.sha256(file_data).hexdigest()

        try:
            with open(kp.encrypted_priv_path, 'rb') as f:
                priv_pem = f.read()
            private_key = load_private_key(priv_pem, key_password)
        except Exception:
            flash('Incorrect key password.', 'danger')
            return render_template('sign_file.html', keys=active_keys)

        try:
            import base64
            signature_bytes = sign_file_data(private_key, file_data)
            signature_b64   = base64.b64encode(signature_bytes).decode()
        except Exception as e:
            flash(f'Signing failed: {str(e)}', 'danger')
            return render_template('sign_file.html', keys=active_keys)

        sf = SignedFile(user_id=current_user.id, key_id=kp.id,
                        filename=secure_filename(file.filename),
                        file_hash=file_hash, signature_b64=signature_b64)
        db.session.add(sf)
        db.session.commit()

        log_action('FILE_SIGN', f'Signed: {file.filename} with key: {kp.key_name}')
        flash('File signed successfully!', 'success')

        sig_info = {
            'sig_id': sf.id,
            'filename': secure_filename(file.filename),
            'sha256': file_hash, 'signature': signature_b64,
            'signed_by': current_user.username, 'key_name': kp.key_name,
            'fingerprint': kp.fingerprint, 'signed_at': sf.signed_at.isoformat(),
            'public_key': kp.public_key_pem,
        }
        return render_template('sign_file.html', keys=active_keys,
                               sig_info=sig_info, sig_json=json.dumps(sig_info, indent=2))

    return render_template('sign_file.html', keys=active_keys)

# Download signature JSON
@app.route('/sign/<int:sig_id>/download')
@user_view_required
def download_sig(sig_id):
    sf = SignedFile.query.filter_by(id=sig_id, user_id=current_user.id).first_or_404()
    kp = KeyPair.query.get(sf.key_id)
    from io import BytesIO
    sig_data = {
        'sig_id': sf.id,
        'filename': sf.filename,
        'sha256': sf.file_hash,
        'signature': sf.signature_b64,
        'signed_by': current_user.username,
        'key_name': kp.key_name if kp else 'unknown',
        'fingerprint': kp.fingerprint if kp else '',
        'signed_at': sf.signed_at.isoformat(),
        'public_key': kp.public_key_pem if kp else '',
    }
    buf = BytesIO(json.dumps(sig_data, indent=2).encode())
    log_action('SIG_DOWNLOAD', f'Downloaded signature for: {sf.filename}')
    return send_file(buf, as_attachment=True,
                     download_name=f'{sf.filename}.sig.json',
                     mimetype='application/json')

# Download encrypted private key
@app.route('/keys/<int:key_id>/download-private', methods=['POST'])
@user_view_required
def download_private_key(key_id):
    kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    key_password = request.form.get('key_password', '')
    # Verify password is correct before allowing download
    try:
        with open(kp.encrypted_priv_path, 'rb') as f:
            priv_pem = f.read()
        load_private_key(priv_pem, key_password)  # will raise if wrong password
    except Exception:
        flash('Incorrect key password — private key not exported.', 'danger')
        return redirect(url_for('manage_keys'))
    from io import BytesIO
    buf = BytesIO(priv_pem)
    log_action('KEY_EXPORT', f'Exported encrypted private key: {kp.key_name}')
    return send_file(buf, as_attachment=True,
                     download_name=f'{kp.key_name.replace(" ", "_")}_private_encrypted.pem',
                     mimetype='application/x-pem-file')

# Encrypt / Decrypt
@app.route('/encrypt', methods=['GET', 'POST'])
@user_view_required
def encrypt_msg():
    all_keys = KeyPair.query.filter_by(is_revoked=False).all()  # can encrypt to any user's public key
    my_keys   = KeyPair.query.filter_by(user_id=current_user.id, is_revoked=False).all()
    result    = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encrypt':
            key_id  = request.form.get('enc_key_id')
            message = request.form.get('message', '').strip()
            if not key_id or not message:
                flash('Please select a key and enter a message.', 'danger')
            else:
                kp = KeyPair.query.get(key_id)
                if kp:
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    pub_key = load_pem_public_key(kp.public_key_pem.encode())
                    encrypted = encrypt_message(pub_key, message.encode('utf-8'))
                    result = {'mode': 'encrypted', 'data': json.dumps(encrypted, indent=2),
                              'key_name': kp.key_name}
                    log_action('MSG_ENCRYPT', f'Encrypted message with key: {kp.key_name}')

        elif action == 'decrypt':
            key_id       = request.form.get('dec_key_id')
            key_password = request.form.get('key_password', '')
            enc_json     = request.form.get('enc_json', '').strip()
            if not key_id or not key_password or not enc_json:
                flash('Please fill in all decryption fields.', 'danger')
            else:
                kp = KeyPair.query.filter_by(id=key_id, user_id=current_user.id).first()
                if not kp:
                    flash('Key not found.', 'danger')
                else:
                    try:
                        with open(kp.encrypted_priv_path, 'rb') as f:
                            priv_pem = f.read()
                        private_key = load_private_key(priv_pem, key_password)
                        enc_data    = json.loads(enc_json)
                        plaintext   = decrypt_message(private_key, enc_data)
                        result      = {'mode': 'decrypted', 'data': plaintext.decode('utf-8'),
                                       'key_name': kp.key_name}
                        log_action('MSG_DECRYPT', f'Decrypted message with key: {kp.key_name}')
                    except (ValueError, KeyError):
                        flash('Incorrect key password.', 'danger')
                    except Exception as e:
                        flash(f'Decryption failed: {str(e)}', 'danger')

    return render_template('encrypt.html', all_keys=all_keys, my_keys=my_keys, result=result)

# Verify Signature
@app.route('/verify', methods=['GET', 'POST'])
@user_view_required
def verify_sig():
    if request.method == 'POST':
        file          = request.files.get('file')
        sig_file      = request.files.get('sig_file')
        pub_key_input = request.form.get('public_key', '').strip()

        if not file or file.filename == '':
            flash('Please upload the file to verify.', 'danger')
            return render_template('verify_file.html')

        file_data   = file.read()
        pub_key_pem = None
        signature_b64 = None
        sig_info    = {}

        if sig_file and sig_file.filename:
            try:
                sig_data      = json.loads(sig_file.read().decode())
                pub_key_pem   = sig_data.get('public_key', '').encode()
                signature_b64 = sig_data.get('signature', '')
                sig_info      = sig_data
            except Exception:
                flash('Invalid signature file format.', 'danger')
                return render_template('verify_file.html')
        elif pub_key_input:
            pub_key_pem   = pub_key_input.encode()
            signature_b64 = request.form.get('signature_b64', '').strip()
        else:
            flash('Please provide a signature file or public key.', 'danger')
            return render_template('verify_file.html')

        try:
            import base64
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            signature_bytes = base64.b64decode(signature_b64)
            public_key      = load_pem_public_key(pub_key_pem)
            valid           = verify_file_signature(public_key, file_data, signature_bytes)
        except Exception as e:
            flash(f'Verification error: {str(e)}', 'danger')
            return render_template('verify_file.html')

        actual_hash = hashlib.sha256(file_data).hexdigest()
        hash_match  = (actual_hash == sig_info.get('sha256', actual_hash))

        log_action('FILE_VERIFY', f'Verified: {file.filename} - {"VALID" if valid else "INVALID"}')
        return render_template('verify_file.html', verified=valid,
                               hash_match=hash_match, actual_hash=actual_hash,
                               sig_info=sig_info, filename=file.filename)

    return render_template('verify_file.html')

# Signing History
@app.route('/history')
@user_view_required
def history():
    sigs = (SignedFile.query.filter_by(user_id=current_user.id)
            .order_by(SignedFile.signed_at.desc()).all())
    return render_template('history.html', sigs=sigs)

# Admin Login - separate from user login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Dedicated admin login page. Only admins can log in here."""
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user     = User.query.filter_by(username=username).first()

        if user and user.is_admin and user.check_password(password):
            if not user.is_active:
                flash('Admin account is deactivated.', 'danger')
                return render_template('admin/login.html')
            login_user(user)
            log_action('ADMIN_LOGIN', f'Admin login: {username}')
            return redirect(url_for('admin_index'))
        else:
            log_action('ADMIN_LOGIN_FAIL', f'Failed admin login for: {username}')
            flash('Invalid admin credentials.', 'danger')

    return render_template('admin/login.html')

# Admin Panel - ALL routes require admin role
# Non-admins are silently redirected to dashboard
@app.route('/admin')
@login_required
@admin_required
def admin_index():
    total_users = User.query.count()
    total_keys  = KeyPair.query.count()
    total_sigs  = SignedFile.query.count()
    total_logs  = AuditLog.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(12).all()
    return render_template('admin/index.html',
                           user_count=total_users,
                           total_users=total_users, total_keys=total_keys,
                           total_sigs=total_sigs, total_logs=total_logs,
                           recent_logs=recent_logs)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users,
                           user_count=_admin_user_count(),
                           now=datetime.utcnow())

@app.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", 'danger')
        return redirect(url_for('admin_users'))
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    log_action('ADMIN_USER_TOGGLE', f'User {user.username} {status}')
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_user_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot change your own role.", 'danger')
        return redirect(url_for('admin_users'))
    user.role = 'user' if user.role == 'admin' else 'admin'
    db.session.commit()
    log_action('ADMIN_ROLE_CHANGE', f'{user.username} role -> {user.role}')
    flash(f'{user.username} is now {user.role}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/block', methods=['POST'])
@login_required
@admin_required
def block_user(user_id):
    """Block a user for a specified number of hours."""
    user  = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot block your own account.", 'danger')
        return redirect(url_for('admin_users'))
    hours = int(request.form.get('block_hours', 1))
    hours = max(1, min(hours, 720))  # 1 hour to 30 days
    user.blocked_until = datetime.utcnow() + timedelta(hours=hours)
    db.session.commit()
    log_action('ADMIN_USER_BLOCK', f'Blocked {user.username} for {hours}h')
    flash(f'{user.username} blocked for {hours} hour(s).', 'warning')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/unblock', methods=['POST'])
@login_required
@admin_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.blocked_until = None
    db.session.commit()
    log_action('ADMIN_USER_UNBLOCK', f'Unblocked {user.username}')
    flash(f'{user.username} has been unblocked.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Permanently delete a user and all their data."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_users'))
    if user.username == ADMIN_USERNAME:
        flash("The default admin account cannot be deleted.", 'danger')
        return redirect(url_for('admin_users'))

    username = user.username
    # Delete encrypted private key files from disk
    for kp in user.keypairs:
        try:
            if os.path.exists(kp.encrypted_priv_path):
                os.remove(kp.encrypted_priv_path)
        except Exception:
            pass
    # Delete audit logs for this user
    AuditLog.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    log_action('ADMIN_USER_DELETE', f'Deleted user: {username}')
    flash(f'User {username} and all their data have been permanently deleted.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_user():
    """Admin can create new admin accounts directly."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role     = request.form.get('role', 'user')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if '@' not in email:
            errors.append('Valid email required.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('admin/create_user.html',
                                   user_count=_admin_user_count())

        # Use placeholder security answers for admin-created accounts
        placeholder = 'admin_created'
        new_user = User(
            username=username, email=email, role=role,
            sec_q1='Admin created account', sec_q2='Admin created account',
            sec_q3='Admin created account',
        )
        new_user.set_password(password)
        new_user.sec_a1_hash = generate_password_hash(placeholder)
        new_user.sec_a2_hash = generate_password_hash(placeholder)
        new_user.sec_a3_hash = generate_password_hash(placeholder)
        db.session.add(new_user)
        db.session.commit()

        log_action('ADMIN_CREATE_USER', f'Admin created user: {username} (role: {role})')
        flash(f'User {username} created as {role}.', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/create_user.html', user_count=_admin_user_count())

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    logs = (AuditLog.query.order_by(AuditLog.timestamp.desc())
            .paginate(page=page, per_page=25, error_out=False))
    return render_template('admin/logs.html', logs=logs,
                           user_count=_admin_user_count())

@app.route('/admin/keys')
@login_required
@admin_required
def admin_keys():
    keys = KeyPair.query.order_by(KeyPair.created_at.desc()).all()
    return render_template('admin/keys.html', keys=keys,
                           user_count=_admin_user_count())

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access Denied'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page Not Found'), 404

# Init DB & seed default admin
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create default admin account if it doesn't exist
        if not User.query.filter_by(username=ADMIN_USERNAME).first():
            placeholder = 'admin_default'
            admin = User(
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                role='admin',
                sec_q1='Admin default account',
                sec_q2='Admin default account',
                sec_q3='Admin default account',
            )
            admin.set_password(ADMIN_PASSWORD)
            admin.sec_a1_hash = generate_password_hash(placeholder)
            admin.sec_a2_hash = generate_password_hash(placeholder)
            admin.sec_a3_hash = generate_password_hash(placeholder)
            db.session.add(admin)
            db.session.commit()
            print(f"Default admin created: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")

        print("Database ready.")
        print("Running on http://127.0.0.1:5001")
        print("Admin panel: http://127.0.0.1:5001/admin")

        # Seed demo/test users if none exist beyond admin
        if User.query.count() <= 1:
            import base64 as _b64
            import hashlib as _hl
            from datetime import datetime as _dt, timedelta as _td
            from crypto_utils import (generate_rsa_keypair, serialize_public_key,
                                      serialize_private_key_encrypted, get_key_fingerprint,
                                      generate_certificate)

            # Use March 1, 2025 as the reference date for all seeded activity
            _BASE = _dt(2025, 3, 1, 12, 0, 0)

            demo_users = [
                dict(username='prakash_thapa',   email='prakash.thapa@example.com',   password='Prakash@123',
                     sq1="What was the name of your first pet?",    sa1="kalu",
                     sq2="What city were you born in?",             sa2="pokhara",
                     sq3="What is your childhood nickname?",        sa3="prak"),
                dict(username='ramesh_koirala',  email='ramesh.koirala@example.com',  password='Ramesh@456',
                     sq1="What is your mother's maiden name?",      sa1="sharma",
                     sq2="What was the make of your first car?",    sa2="suzuki",
                     sq3="What street did you grow up on?",         sa3="lakeside road"),
                dict(username='sandeep_basnet',  email='sandeep.basnet@example.com',  password='Sandeep@789',
                     sq1="What was the name of your primary school?", sa1="bal vidya",
                     sq2="What is the name of your oldest sibling?",  sa2="binod",
                     sq3="What is the name of your favourite teacher?", sa3="sir ram"),
                dict(username='anil_gurung',     email='anil.gurung@example.com',     password='Anil@1011',
                     sq1="What was the name of your first pet?",    sa1="tiger",
                     sq2="What city were you born in?",             sa2="butwal",
                     sq3="What is your childhood nickname?",        sa3="anil dai"),
                dict(username='bikash_shrestha', email='bikash.shrestha@example.com', password='Bikash@1213',
                     sq1="What is your mother's maiden name?",      sa1="pradhan",
                     sq2="What was the make of your first car?",    sa2="hyundai",
                     sq3="What street did you grow up on?",         sa3="new road"),
                dict(username='sunita_adhikari', email='sunita.adhikari@example.com', password='Sunita@1415',
                     sq1="What was the name of your primary school?", sa1="shree school",
                     sq2="What is the name of your oldest sibling?",  sa2="sita",
                     sq3="What is your childhood nickname?",          sa3="sunny"),
                dict(username='manisha_poudel',  email='manisha.poudel@example.com',  password='Manisha@1617',
                     sq1="What was the name of your first pet?",    sa1="motu",
                     sq2="What city were you born in?",             sa2="kathmandu",
                     sq3="What is the name of your favourite teacher?", sa3="miss maya"),
                dict(username='rachana_bhatta',  email='rachana.bhatta@example.com',  password='Rachana@1819',
                     sq1="What is your mother's maiden name?",      sa1="thapa",
                     sq2="What was the make of your first car?",    sa2="toyota",
                     sq3="What street did you grow up on?",         sa3="baneshwor"),
                dict(username='sushma_maharjan', email='sushma.maharjan@example.com', password='Sushma@2021',
                     sq1="What was the name of your primary school?", sa1="nepal rastriya",
                     sq2="What is the name of your oldest sibling?",  sa2="suresh",
                     sq3="What is your childhood nickname?",          sa3="sushu"),
                dict(username='anjana_kharel',   email='anjana.kharel@example.com',   password='Anjana@2223',
                     sq1="What was the name of your first pet?",    sa1="lali",
                     sq2="What city were you born in?",             sa2="biratnagar",
                     sq3="What is the name of your favourite teacher?", sa3="sir hari"),
            ]

            key_configs = [
                ('prakash-signing-key',  2048), ('ramesh-primary-key',   2048),
                ('sandeep-release-key',  4096), ('anil-signing-key',     2048),
                ('bikash-primary-key',   3072), ('sunita-signing-key',   2048),
                ('manisha-release-key',  4096), ('rachana-primary-key',  2048),
                ('sushma-signing-key',   3072), ('anjana-primary-key',   2048),
            ]
            fake_files_pool = [
                'project_report.pdf', 'release_v2.1.zip', 'contract_draft.docx',
                'config_backup.json', 'audit_log.txt',    'source_code.tar.gz',
                'invoice_march.pdf',  'deployment.yaml',  'readme.md',
                'test_results.xml',   'budget_2025.xlsx', 'design_spec.pdf',
            ]

            created_users = []
            for i, ud in enumerate(demo_users):
                reg_date = _BASE - _td(days=12 - i)   # registrations spread Feb 17 – Mar 1
                u = User(username=ud['username'], email=ud['email'], role='user',
                         sec_q1=ud['sq1'], sec_q2=ud['sq2'], sec_q3=ud['sq3'],
                         created_at=reg_date)
                u.set_password(ud['password'])
                u.set_security_answers(ud['sa1'], ud['sa2'], ud['sa3'])
                db.session.add(u)
                db.session.flush()
                created_users.append((u, reg_date))

            db.session.commit()

            for i, (user, reg_date) in enumerate(created_users):
                kname, ksize = key_configs[i]
                priv, pub = generate_rsa_keypair(ksize)
                pub_pem = serialize_public_key(pub)
                fp = get_key_fingerprint(pub)
                cert_pem = generate_certificate(priv, pub, user.username)

                priv_filename = f"priv_{user.id}_{int(_BASE.timestamp()) + i}.pem"
                priv_path = os.path.join(app.config['KEYSTORE_FOLDER'], priv_filename)
                with open(priv_path, 'wb') as fh:
                    fh.write(serialize_private_key_encrypted(priv, 'demo_password'))

                key_date = reg_date + _td(hours=3)
                kp = KeyPair(user_id=user.id, key_name=kname,
                             public_key_pem=pub_pem.decode(),
                             encrypted_priv_path=priv_path,
                             fingerprint=fp, key_size=ksize,
                             certificate_pem=cert_pem.decode(),
                             created_at=key_date)
                db.session.add(kp)
                db.session.flush()

                # 2–3 signed files per user, spread across Feb 17 – Mar 1
                files_for_user = fake_files_pool[(i * 2) % len(fake_files_pool):
                                                  (i * 2) % len(fake_files_pool) + 3]
                for j, fname in enumerate(files_for_user):
                    sign_date = reg_date + _td(days=1 + j, hours=2 + j)
                    fake_hash = _hl.sha256(f"{user.username}{fname}{j}".encode()).hexdigest()
                    fake_sig  = _b64.b64encode(os.urandom(256)).decode()
                    sf = SignedFile(user_id=user.id, key_id=kp.id,
                                   filename=fname, file_hash=fake_hash,
                                   signature_b64=fake_sig, signed_at=sign_date)
                    db.session.add(sf)

                for action, detail, days_offset in [
                    ('REGISTER',     f'New user registered: {user.username}',          0),
                    ('LOGIN',        'Successful login',                                0),
                    ('KEY_GENERATE', f'Generated {ksize}-bit RSA key: {kname}',        0),
                    ('FILE_SIGN',    f'Signed: {fake_files_pool[(i*2)%len(fake_files_pool)]} with key: {kname}', 1),
                ]:
                    db.session.add(AuditLog(
                        user_id=user.id, username=user.username,
                        action=action, details=detail,
                        ip_address='127.0.0.1',
                        timestamp=reg_date + _td(days=days_offset, hours=1)
                    ))

            db.session.commit()
            print("Demo users seeded: prakash_thapa, ramesh_koirala, sandeep_basnet, anil_gurung, bikash_shrestha, sunita_adhikari, manisha_poudel, rachana_bhatta, sushma_maharjan, anjana_kharel")

    app.run(debug=True, port=5001)
