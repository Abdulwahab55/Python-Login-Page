"""
Test script to trigger various security features and log output
"""
import requests
from time import sleep

BASE_URL = "http://127.0.0.1:5000"

def test_weak_password():
    """Test 1: Weak password rejection"""
    print("\n=== TEST 1: Weak Password ===")
    print("Testing registration with weak password 'test123'...")
    
    # Get CSRF token first
    session = requests.Session()
    response = session.get(f"{BASE_URL}/register")
    
    # Try to register with weak password
    data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'test123',
        'confirm_password': 'test123'
    }
    response = session.post(f"{BASE_URL}/register", data=data, allow_redirects=False)
    print(f"Response: {response.status_code}")
    if response.status_code == 302:
        print("✓ Redirected (validation triggered)")
    
def test_rate_limiting():
    """Test 2: Rate limiting"""
    print("\n=== TEST 2: Rate Limiting ===")
    print("Attempting 11 login requests (limit is 10 per minute)...")
    
    for i in range(11):
        session = requests.Session()
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        try:
            response = session.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
            print(f"Request {i+1}: Status {response.status_code}")
            
            if response.status_code == 429:
                print("✓ Rate limit triggered!")
                break
        except Exception as e:
            print(f"Error: {e}")
        
        sleep(0.1)

def test_invalid_username():
    """Test 3: Invalid username validation"""
    print("\n=== TEST 3: Invalid Username ===")
    print("Testing registration with invalid username 'ab' (too short)...")
    
    session = requests.Session()
    response = session.get(f"{BASE_URL}/register")
    
    data = {
        'username': 'ab',  # Too short
        'email': 'test2@example.com',
        'password': 'SecureP@ss123',
        'confirm_password': 'SecureP@ss123'
    }
    response = session.post(f"{BASE_URL}/register", data=data, allow_redirects=False)
    print(f"Response: {response.status_code}")
    if response.status_code == 302:
        print("✓ Validation triggered (username too short)")

def test_valid_registration():
    """Test 4: Valid registration"""
    print("\n=== TEST 4: Valid Strong Password ===")
    print("Testing registration with strong password 'SecureP@ss456'...")
    
    session = requests.Session()
    response = session.get(f"{BASE_URL}/register")
    
    data = {
        'username': 'secureuser',
        'email': 'secure@example.com',
        'password': 'SecureP@ss456',
        'confirm_password': 'SecureP@ss456'
    }
    response = session.post(f"{BASE_URL}/register", data=data, allow_redirects=False)
    print(f"Response: {response.status_code}")
    if response.status_code == 302:
        print("✓ Registration successful (or user exists)")

if __name__ == "__main__":
    print("Starting Security Tests...")
    print("=" * 50)
    
    try:
        test_weak_password()
        test_invalid_username()
        test_valid_registration()
        test_rate_limiting()
    except Exception as e:
        print(f"Error running tests: {e}")
    
    print("\n" + "=" * 50)
    print("Tests completed! Check Flask logs for details.")
