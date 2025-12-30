import requests
import re
import pyotp
import time

BASE_URL = "http://127.0.0.1:5000"

def get_csrf_token(response_text):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    return match.group(1) if match else None

def verify_change_username():
    username = f'u_{int(time.time())}'
    email = f'{username}@example.com'
    password = 'StrongPass@123'
    new_username = f'n_{username}'
    
    print(f"\n=== Testing Change Username ({username} -> {new_username}) ===")
    
    session = requests.Session()
    
    # 1. Register & Setup 2FA
    print("1. Registering...")
    resp = session.get(f"{BASE_URL}/register")
    csrf = get_csrf_token(resp.text)
    
    data = {
        'username': username,
        'email': email,
        'password': password,
        'confirm_password': password,
        'csrf_token': csrf
    }
    resp = session.post(f"{BASE_URL}/register", data=data)
    
    # 2FA Setup
    from app import app, User
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        secret = user.two_factor_secret
    
    totp = pyotp.TOTP(secret)
    token = totp.now()
    resp = session.post(f"{BASE_URL}/complete-2fa-setup", data={'token': token, 'csrf_token': csrf})
    
    print("   -> Registered & Logged In")
    
    # 2. Go to Profile
    print("2. Visiting Profile...")
    resp = session.get(f"{BASE_URL}/profile")
    if username not in resp.text:
         print("FAIL: Profile does not show current username")
         return False
    
    # 3. Change Username (Success Case)
    print(f"3. Changing username to {new_username}...")
    csrf = get_csrf_token(resp.text)
    data = {
        'new_username': new_username,
        'password': password,
        'csrf_token': csrf
    }
    resp = session.post(f"{BASE_URL}/change-username", data=data)
    
    if new_username not in resp.text:
        print(f"FAIL: Profile does not show NEW username.")
        print(f"   -> Status Code: {resp.status_code}")
        print(f"   -> Response Start: {resp.text[:500]}")
        # Try to find flash messages
        flashes = re.findall(r'alert-\w+">([^<]+)<', resp.text)
        if flashes:
            print(f"   -> Flash Messages Found: {flashes}")
        else:
            print("   -> No flash messages found.")
        return False
        
    if "Username changed successfully" not in resp.text:
         print("FAIL: Success message not found")
         return False
         
    print("   -> Username Change Successful")
    
    # 4. Verify DB Update
    with app.app_context():
        u = User.query.filter_by(username=new_username).first()
        if not u:
            print("FAIL: User not found in DB with new username")
            return False
        old = User.query.filter_by(username=username).first()
        if old:
             print("FAIL: Old username still exists in DB (should be renamed)")
             return False
             
    print("   -> DB Verified")
    
    # 5. Logout & Login with New Username
    print("5. Relogging with new username...")
    session.get(f"{BASE_URL}/logout")
    
    resp = session.get(f"{BASE_URL}/login")
    csrf = get_csrf_token(resp.text)
    data = {
        'username': new_username,
        'password': password,
        'csrf_token': csrf
    }
    resp = session.post(f"{BASE_URL}/login", data=data)
    
    # 2FA Verify
    token = totp.now()
    resp = session.post(f"{BASE_URL}/verify-2fa", data={'token': token, 'csrf_token': csrf})
    
    if "congrats" in resp.url or "dashboard" in resp.url or "Welcome" in resp.text:
         print("   -> Login Success")
    else:
         print(f"FAIL: Could not login with new username. URL: {resp.url}")
         return False

    return True

if __name__ == "__main__":
    if verify_change_username():
        print("\nTEST PASSED")
    else:
        print("\nTEST FAILED")
