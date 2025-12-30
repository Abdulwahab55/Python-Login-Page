"""
Python Login Page Application
A secure Flask-based login and registration system with user authentication
SECURITY FIX: User enumeration vulnerability patched
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import re
import pyotp
import qrcode
import io
import base64
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 1800)))

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
)

db = SQLAlchemy(app)


# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Two-Factor Authentication fields
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    
    # Admin fields
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<User {self.username}>'


# Create database tables and default admin user
with app.app_context():
    db.create_all()
    
    # Create default admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        default_password = 'Admin@123'
        hashed_password = generate_password_hash(default_password, method='pbkdf2:sha256')
        admin_secret = pyotp.random_base32()
        
        admin = User(
            username='admin',
            email='admin@pythonlogin.com',
            password=hashed_password,
            is_admin=True,
            must_change_password=True,
            two_factor_enabled=True,  # Admin requires 2FA
            two_factor_secret=admin_secret
        )
        
        db.session.add(admin)
        db.session.commit()
        
        # Print admin credentials and 2FA secret
        totp = pyotp.TOTP(admin_secret)
        print('='*60)
        print('Default admin user created:')
        print('Username: admin')
        print('Password: Admin@123')
        print(f'2FA Secret: {admin_secret}')
        print(f'Current 2FA Token: {totp.now()}')
        print('='*60)
        print('⚠️  IMPORTANT:')
        print('1. Change password on first login')
        print('2. Add the 2FA secret to your authenticator app')
        print('3. Use the token from your app to login')
        print('='*60)


# Input Validation Functions
def validate_username(username):
    """Validate username: 3-20 alphanumeric characters and underscores"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None


def validate_email(email):
    """Validate email format"""
    if not email or len(email) > 120:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password strength:
    - At least 8 characters
    - Contains uppercase and lowercase
    - Contains at least one digit
    - Contains at least one special character
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*...)"
    
    return True, "Password is strong"


@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            return render_template('dashboard.html', user=user)
        session.clear()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """
    User registration with enhanced security
    SECURITY FIX: Prevents user enumeration through timing attacks and generic responses
    """
    if request.method == 'POST':
        # Record start time for timing attack prevention
        start_time = time.time()
        
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Track if registration will succeed (for timing normalization)
        registration_will_succeed = False
        error_message = None
        
        # Validation
        if not username or not email or not password:
            error_message = 'All fields are required!'
        
        # Validate username
        elif not validate_username(username):
            error_message = 'Username must be 3-20 characters long and contain only letters, numbers, and underscores'
        
        # Validate email
        elif not validate_email(email):
            error_message = 'Please enter a valid email address'
        
        # Validate password match
        elif password != confirm_password:
            error_message = 'Passwords do not match!'
        
        # Validate password strength
        else:
            is_valid, message = validate_password(password)
            if not is_valid:
                error_message = message
        
        # If validation passed, check for existing user and process
        if not error_message:
            # Check if user already exists
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                # SECURITY FIX: Always hash the password even if user exists
                # This prevents timing attacks that could reveal if username exists
                _ = generate_password_hash(password, method='pbkdf2:sha256')
                
                # SECURITY FIX: Use generic message that doesn't reveal if user exists
                error_message = 'Registration could not be completed. Please try different credentials or contact support if you believe this is an error.'
            else:
                # User doesn't exist, proceed with registration
                registration_will_succeed = True
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                two_factor_secret = pyotp.random_base32()
                new_user = User(
                    username=username, 
                    email=email, 
                    password=hashed_password,
                    two_factor_secret=two_factor_secret,
                    two_factor_enabled=True
                )
                
                try:
                    db.session.add(new_user)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f'Registration error: {str(e)}')
                    error_message = 'فشل التسجيل. الرجاء المحاولة مرة أخرى.'
                    registration_will_succeed = False
        
        # SECURITY FIX: Normalize response time
        elapsed_time = time.time() - start_time
        target_time = 0.3
        if elapsed_time < target_time:
            time.sleep(target_time - elapsed_time)
        
        if error_message:
            flash(error_message, 'error')
            return redirect(url_for('register_ar'))
        
        if registration_will_succeed:
            flash('تم التسجيل بنجاح! الرجاء تسجيل الدخول.', 'success')
            return redirect(url_for('login_ar'))
    
    return render_template('register_ar.html')


@app.route('/ar/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login_ar():
    """Arabic version - User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('اسم المستخدم وكلمة المرور مطلوبان!', 'error')
            return redirect(url_for('login_ar'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            return redirect(url_for('congrats_ar'))
        else:
            flash('بيانات اعتماد غير صحيحة. الرجاء المحاولة مرة أخرى.', 'error')
            return redirect(url_for('login_ar'))
    
    return render_template('login_ar.html')


@app.route('/ar/dashboard')
def dashboard_ar():
    """Arabic version - User dashboard"""
    if 'user_id' not in session:
        flash('الرجاء تسجيل الدخول أولاً!', 'error')
        return redirect(url_for('login_ar'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مرة أخرى.', 'error')
        return redirect(url_for('login_ar'))
    
    return render_template('dashboard_ar.html', user=user)


@app.route('/ar/congrats')
def congrats_ar():
    """Arabic version - Congratulations page"""
    if 'user_id' not in session:
        flash('الرجاء تسجيل الدخول أولاً!', 'error')
        return redirect(url_for('login_ar'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مرة أخرى.', 'error')
        return redirect(url_for('login_ar'))
    
    current_time = datetime.now().strftime('%d %B %Y في %I:%M %p')
    return render_template('congrats_ar.html', user=user, current_time=current_time)


@app.route('/ar/profile')
def profile_ar():
    """Arabic version - User profile"""
    if 'user_id' not in session:
        flash('الرجاء تسجيل الدخول أولاً!', 'error')
        return redirect(url_for('login_ar'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مرة أخرى.', 'error')
        return redirect(url_for('login_ar'))
    
    return render_template('profile_ar.html', user=user)


@app.route('/ar/logout')
def logout_ar():
    """Arabic version - User logout"""
    session.clear()
    flash('تم تسجيل الخروج بنجاح!', 'success')
    return redirect(url_for('login_ar'))


if __name__ == '__main__':
    # Never run with debug=True in production
    debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(debug=debug_mode, host='127.0.0.1', port=5000).add(new_user)
                    db.session.commit()
                    
                    # Store user info in session for 2FA setup
                    session['setup_user_id'] = new_user.id
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f'Registration error: {str(e)}')
                    error_message = 'Registration failed. Please try again.'
                    registration_will_succeed = False
        
        # SECURITY FIX: Normalize response time to prevent timing attacks
        # Target: 300ms minimum response time
        elapsed_time = time.time() - start_time
        target_time = 0.3  # 300ms
        if elapsed_time < target_time:
            time.sleep(target_time - elapsed_time)
        
        # Return appropriate response
        if error_message:
            flash(error_message, 'error')
            return redirect(url_for('register'))
        
        if registration_will_succeed:
            return redirect(url_for('first_time_2fa_setup'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """User login with enhanced security"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Check if account is active
            if not user.is_active:
                flash('Your account has been deactivated. Please contact administrator.', 'error')
                return redirect(url_for('login'))
            
            # Check if password must be changed
            if user.must_change_password:
                session['change_password_user_id'] = user.id
                return redirect(url_for('force_change_password'))
            
            # Check if 2FA is enabled
            if user.two_factor_enabled:
                # Store user_id temporarily for 2FA verification
                session['temp_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            
            # Regenerate session to prevent session fixation
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session.permanent = True
            
            # Redirect admin to admin dashboard
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            
            return redirect(url_for('congrats'))
        else:
            # Generic error message to prevent username enumeration
            flash('Invalid credentials. Please try again.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', user=user)


@app.route('/congrats')
def congrats():
    """Congratulations page after successful login"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    current_time = datetime.now().strftime('%B %d, %Y at %I:%M %p')
    return render_template('congrats.html', user=user, current_time=current_time)


@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user)


# ==================== Two-Factor Authentication Routes ====================

@app.route('/first-time-2fa-setup')
def first_time_2fa_setup():
    """First-time 2FA setup after registration"""
    if 'setup_user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['setup_user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Generate QR code
    totp = pyotp.TOTP(user.two_factor_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='Python Login Page'
    )
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('first_time_2fa_setup.html', 
                          qr_code=qr_code_base64,
                          secret=user.two_factor_secret)


@app.route('/complete-2fa-setup', methods=['POST'])
@limiter.limit("5 per minute")
def complete_2fa_setup():
    """Complete first-time 2FA setup and login"""
    if 'setup_user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['setup_user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    token = request.form.get('token', '').strip()
    
    # Verify the token
    totp = pyotp.TOTP(user.two_factor_secret)
    if totp.verify(token, valid_window=1):
        # Token is valid, complete registration and login
        setup_id = session.pop('setup_user_id')
        session.clear()
        session['user_id'] = setup_id
        session['username'] = user.username
        session.permanent = True
        flash('Registration and 2FA setup successful!', 'success')
        return redirect(url_for('congrats'))
    else:
        flash('Invalid token. Please try again.', 'error')
        return redirect(url_for('first_time_2fa_setup'))


@app.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    """Verify 2FA token during login"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        user = db.session.get(User, session['temp_user_id'])
        if not user:
            session.clear()
            flash('Invalid session. Please login again.', 'error')
            return redirect(url_for('login'))
        
        # Verify the token
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(token, valid_window=1):
            # Token is valid, complete login
            temp_id = session.pop('temp_user_id')
            session.clear()
            session['user_id'] = temp_id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session.permanent = True
            flash('2FA verification successful!', 'success')
            return redirect(url_for('congrats'))
        else:
            flash('Invalid 2FA token. Please try again.', 'error')
            return redirect(url_for('verify_2fa'))
    
    return render_template('verify_2fa.html')


@app.route('/setup-2fa')
def setup_2fa():
    """Setup Two-Factor Authentication"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Generate a new secret if not already present
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()
    
    # Generate QR code
    totp = pyotp.TOTP(user.two_factor_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='Python Login Page'
    )
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', 
                          qr_code=qr_code_base64,
                          secret=user.two_factor_secret)


@app.route('/enable-2fa', methods=['POST'])
@limiter.limit("5 per minute")
def enable_2fa():
    """Enable 2FA after verification"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    token = request.form.get('token', '').strip()
    
    # Verify the token
    totp = pyotp.TOTP(user.two_factor_secret)
    if totp.verify(token, valid_window=1):
        user.two_factor_enabled = True
        db.session.commit()
        flash('Two-Factor Authentication enabled successfully!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Invalid token. Please try again.', 'error')
        return redirect(url_for('setup_2fa'))


@app.route('/disable-2fa', methods=['POST'])
@limiter.limit("5 per minute")
def disable_2fa():
    """Disable Two-Factor Authentication"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    password = request.form.get('password', '')
    
    # Verify password before disabling 2FA
    if check_password_hash(user.password, password):
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.session.commit()
        flash('Two-Factor Authentication disabled successfully!', 'success')
    else:
        flash('Invalid password. Cannot disable 2FA.', 'error')
    
    return redirect(url_for('profile'))


# Security Headers
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ==================== Admin Routes ====================

@app.route('/force-change-password', methods=['GET', 'POST'])
def force_change_password():
    """Force password change on first login"""
    if 'change_password_user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['change_password_user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Verify current password
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect!', 'error')
            return redirect(url_for('force_change_password'))
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return redirect(url_for('force_change_password'))
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('force_change_password'))
        
        # Update password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.must_change_password = False
        db.session.commit()
        
        # Complete login
        user_id = session.pop('change_password_user_id')
        session.clear()
        session['user_id'] = user_id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        session.permanent = True
        
        flash('Password changed successfully!', 'success')
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('congrats'))
    
    return render_template('force_change_password.html', user=user)


@app.route('/admin')
def admin_dashboard():
    """Admin dashboard"""
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    return render_template('admin_dashboard.html', 
                          users=users,
                          total_users=total_users,
                          active_users=active_users,
                          admin_users=admin_users)


@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
def admin_toggle_user_status(user_id):
    """Toggle user active status"""
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if user.is_admin and user.id != session['user_id']:
        flash('Cannot deactivate other admin accounts!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    """Delete user"""
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if user.is_admin:
        flash('Cannot delete admin accounts!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been deleted!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/reset-2fa', methods=['POST'])
def admin_reset_2fa(user_id):
    """Reset user's 2FA"""
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user.two_factor_enabled = False
    user.two_factor_secret = None
    db.session.commit()
    
    flash(f'2FA has been reset for user {user.username}!', 'success')
    return redirect(url_for('admin_dashboard'))


# ==================== Arabic Language Routes ====================

@app.route('/ar/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register_ar():
    """
    Arabic version - User registration
    SECURITY FIX: Prevents user enumeration through timing attacks and generic responses
    """
    if request.method == 'POST':
        # Record start time for timing attack prevention
        start_time = time.time()
        
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        registration_will_succeed = False
        error_message = None
        
        if not username or not email or not password:
            error_message = 'جميع الحقول مطلوبة!'
        
        elif not validate_username(username):
            error_message = 'يجب أن يكون اسم المستخدم من 3-20 حرفاً ويحتوي فقط على أحرف وأرقام وشرطة سفلية'
        
        elif not validate_email(email):
            error_message = 'الرجاء إدخال عنوان بريد إلكتروني صحيح'
        
        elif password != confirm_password:
            error_message = 'كلمات المرور غير متطابقة!'
        
        else:
            is_valid, _ = validate_password(password)
            if not is_valid:
                error_message = 'كلمة المرور يجب أن تكون 8 أحرف على الأقل وتحتوي على أحرف كبيرة وصغيرة وأرقام ورموز خاصة'
        
        if not error_message:
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                # SECURITY FIX: Always hash password even if user exists
                _ = generate_password_hash(password, method='pbkdf2:sha256')
                error_message = 'لا يمكن إتمام التسجيل. الرجاء استخدام بيانات مختلفة أو الاتصال بالدعم إذا كنت تعتقد أن هذا خطأ.'
            else:
                registration_will_succeed = True
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, email=email, password=hashed_password)
                
                try:
                    db.session