# Python Login Page

A simple and secure Flask-based login and registration system with user authentication.

## Features

- ✅ User Registration
- ✅ User Login
- ✅ Secure Password Hashing (Werkzeug)
- ✅ Session Management
- ✅ User Dashboard
- ✅ User Profile
- ✅ SQLite Database
- ✅ Flash Messages
- ✅ Modern Responsive UI

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Abdulwahab55/Python-Login-Page.git
cd Python-Login-Page
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Register**: Create a new account with username, email, and password
2. **Login**: Access your account with username and password
3. **Dashboard**: View your personalized dashboard after login
4. **Profile**: View your profile information
5. **Logout**: Securely logout from your account

## Security Features

- Password hashing using Werkzeug's `generate_password_hash`
- Session-based authentication
- Input validation
- SQL injection protection (SQLAlchemy ORM)
- CSRF protection ready

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Security**: Werkzeug
- **ORM**: SQLAlchemy
- **Frontend**: HTML, CSS, Bootstrap

## Project Structure

```
Python-Login-Page/
├── app.py                  # Main application
├── requirements.txt        # Dependencies
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User dashboard
│   └── profile.html      # User profile
├── static/               # Static files
│   └── style.css        # Custom styles
└── README.md            # This file
```

## License

MIT License

## Author

Abdulwahab A. Alessa
