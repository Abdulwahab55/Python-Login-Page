import requests
import re
from app import app, db, User

BASE_URL = "http://127.0.0.1:5000"

def test_ar_login_2fa_enforcement():
    print("\n=== TEST: Arabic Login 2FA Enforcement ===")
    
    # 1. Create a user with 2FA enabled directly in DB to be sure
    with app.app_context():
        # Clean up old test user
        old = User.query.filter_by(username='artest').first()
        if old:
            db.session.delete(old)
            db.session.commit()
            
        from werkzeug.security import generate_password_hash
        import pyotp
        
        u = User(
            username='artest',
            email='artest@example.com',
            password=generate_password_hash('Pass@123', method='pbkdf2:sha256'),
            two_factor_enabled=True,
            two_factor_secret=pyotp.random_base32(),
            is_active=True
        )
        db.session.add(u)
        db.session.commit()
        print("Created test user 'artest' with 2FA enabled.")

    # 2. Try to login via Arabic route
    session = requests.Session()
    # Get CSRF token
    resp = session.get(f"{BASE_URL}/ar/login")
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    if not csrf_match:
        print("Failed to get CSRF token")
        return False
    csrf_token = csrf_match.group(1)
    
    data = {
        'username': 'artest',
        'password': 'Pass@123',
        'csrf_token': csrf_token
    }
    
    print("Attempting login to /ar/login...")
    # Follow redirects to see where we land
    resp = session.post(f"{BASE_URL}/ar/login", data=data, allow_redirects=True)
    
    print(f"Final URL: {resp.url}")
    
    if "verify-2fa" in resp.url or "Two-Factor" in resp.text or "verify_2fa" in resp.text:
        print("SUCCESS: Redirected to 2FA verification page.")
        return True
    elif "congrats" in resp.url or "Congratulations" in resp.text:
        print("FAILURE: Bypassed 2FA and went straight to dashboard!")
        return False
    else:
        print(f"UNKNOWN: Landed on {resp.url}")
        return False

if __name__ == "__main__":
    try:
        if test_ar_login_2fa_enforcement():
            exit(0)
        else:
            exit(1)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
