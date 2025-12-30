import requests
import re
import pyotp
import time

BASE_URL = "http://127.0.0.1:5000"

def get_csrf_token(response_text):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    return match.group(1) if match else None

def verify_password_change():
    username = f'u_pwd_{int(time.time())}'
    email = f'{username}@example.com'
    old_password = 'OldStrongPass@123'
    new_password = 'NewStrongPass@456'
    
    print(f"\n=== Testing Change Password ({username}) ===")
    
    session = requests.Session()
    
    # 1. Register & Setup 2FA
    print("1. Registering...")
    resp = session.get(f"{BASE_URL}/register")
    csrf = get_csrf_token(resp.text)
    
    data = {
        'username': username,
        'email': email,
        'password': old_password,
        'confirm_password': old_password,
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
    if 'name="current_password"' not in resp.text:
         print("FAIL: Profile does not show 'Change Password' form (field 'current_password' not found)")
         # Debug print
         print(f"DEBUG: Response snippet: {resp.text[:500]}")
         return False
    
    # 3. Change Password
    print(f"3. Changing password...")
    csrf = get_csrf_token(resp.text)
    data = {
        'current_password': old_password,
        'new_password': new_password,
        'confirm_password': new_password,
        'csrf_token': csrf
    }
    resp = session.post(f"{BASE_URL}/change-password", data=data)
    
    if "Password changed successfully" not in resp.text:
        print(f"FAIL: Success message not found.")
        print(f"   -> Status Code: {resp.status_code}")
        flashes = re.findall(r'alert-\w+">([^<]+)<', resp.text)
        if flashes:
            print(f"   -> Flashes: {flashes}")
        return False
         
    print("   -> Password Change Requested")
    
    # 4. Logout
    print("4. Logging out...")
    session.get(f"{BASE_URL}/logout")
    
    # 5. Try Login with OLD Password (Should Fail)
    print("5. Attempting login with OLD password (should fail)...")
    resp = session.get(f"{BASE_URL}/login")
    csrf = get_csrf_token(resp.text)
    data = {
        'username': username,
        'password': old_password,
        'csrf_token': csrf
    }
    resp = session.post(f"{BASE_URL}/login", data=data)
    
    if "login_success" in resp.url or "dashboard" in resp.url or "Welcome" in resp.text:
        print("FAIL: Logged in with OLD password!")
        return False
    else:
        print("   -> Login with old password failed (as expected)")

    # 6. Try Login with NEW Password (Should Success)
    print("6. Attempting login with NEW password (should success)...")
    data['password'] = new_password
    resp = session.post(f"{BASE_URL}/login", data=data)
    
    # 2FA Verify
    token = totp.now()
    resp = session.post(f"{BASE_URL}/verify-2fa", data={'token': token, 'csrf_token': csrf})
    
    if "congrats" in resp.url or "dashboard" in resp.url or "Welcome" in resp.text:
         print("   -> Login with NEW password SUCCESS")
    else:
         print(f"FAIL: Could not login with new password. URL: {resp.url}")
         return False

    return True

if __name__ == "__main__":
    if verify_password_change():
        print("\nTEST PASSED")
    else:
        print("\nTEST FAILED")
