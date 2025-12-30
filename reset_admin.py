from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    user = User.query.filter_by(username='admin').first()
    if user:
        user.password = generate_password_hash('Admin@123', method='pbkdf2:sha256')
        db.session.commit()
        print("Admin password reset to: Admin@123")
    else:
        print("Admin user not found. Creating one...")
        # Create if missing (though app.py usually does this)
        hashed_password = generate_password_hash('Admin@123', method='pbkdf2:sha256')
        new_admin = User(
            username='admin', 
            email='admin@pythonlogin.com', 
            password=hashed_password,
            is_admin=True,
            must_change_password=True,
            two_factor_enabled=True
        )
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created with password: Admin@123")
