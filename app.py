"""
Python Login Page Application
A secure Flask-based login and registration system with user authentication
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
    
    def __repr__(self):
        return f'<User {self.username}>'


# Create database tables
with app.app_context():
    db.create_all()


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
    """User registration with enhanced security"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        # Validate username
        if not validate_username(username):
            flash('Username must be 3-20 characters long and contain only letters, numbers, and underscores', 'error')
            return redirect(url_for('register'))
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register'))
        
        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists (prevent username enumeration with generic message)
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Registration failed. Please try different credentials.', 'error')
            return redirect(url_for('register'))
        
        # Create new user with hashed password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))
    
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
            # Regenerate session to prevent session fixation
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
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


# ==================== Arabic Language Routes ====================

@app.route('/ar/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register_ar():
    """Arabic version - User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('جميع الحقول مطلوبة!', 'error')
            return redirect(url_for('register_ar'))
        
        if not validate_username(username):
            flash('يجب أن يكون اسم المستخدم من 3-20 حرفاً ويحتوي فقط على أحرف وأرقام وشرطة سفلية', 'error')
            return redirect(url_for('register_ar'))
        
        if not validate_email(email):
            flash('الرجاء إدخال عنوان بريد إلكتروني صحيح', 'error')
            return redirect(url_for('register_ar'))
        
        if password != confirm_password:
            flash('كلمات المرور غير متطابقة!', 'error')
            return redirect(url_for('register_ar'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل وتحتوي على أحرف كبيرة وصغيرة وأرقام ورموز خاصة', 'error')
            return redirect(url_for('register_ar'))
        
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('فشل التسجيل. الرجاء استخدام بيانات مختلفة.', 'error')
            return redirect(url_for('register_ar'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('تم التسجيل بنجاح! الرجاء تسجيل الدخول.', 'success')
            return redirect(url_for('login_ar'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('فشل التسجيل. الرجاء المحاولة مرة أخرى.', 'error')
            return redirect(url_for('register_ar'))
    
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
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)
