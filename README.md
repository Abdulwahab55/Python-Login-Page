# Python Login Page

A simple and secure Flask-based login and registration system with user authentication and modern UI features.

## Features

- ✅ User Registration with Password Confirmation
- ✅ User Login with Authentication
- ✅ Secure Password Hashing (Werkzeug)
- ✅ Session Management
- ✅ User Dashboard
- ✅ User Profile Page
- ✅ Congratulations Page after Login
- ✅ SQLite Database
- ✅ Success Popup Notifications
- ✅ Flash Messages for Errors
- ✅ Modern Responsive UI with Gradient Design
- ✅ Form Validation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Abdulwahab55/Python-Login-Page.git
cd Python-Login-Page
```

2. Create a virtual environment (recommended):
```bash
python -m venv .venv
.venv\Scripts\activate  # On Windows
source .venv/bin/activate  # On macOS/Linux
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

5. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Register**: Create a new account with username, email, and password
   - Password must be at least 6 characters
   - Passwords must match
   - Success popup notification appears after registration
2. **Login**: Access your account with username and password
   - Redirected to congratulations page upon successful login
3. **Congratulations Page**: Welcome page with user info and quick links
4. **Dashboard**: View your personalized dashboard with account information
5. **Profile**: View detailed profile information
6. **Logout**: Securely logout from your account

## Security Features

- Password hashing using Werkzeug's `pbkdf2:sha256`
- Session-based authentication
- Input validation and sanitization
- Password confirmation on registration
- Minimum password length requirement (6 characters)
- SQL injection protection (SQLAlchemy ORM)
- Unique username and email constraints
- Secure session management with secret key

## Technology Stack

- **Backend**: Flask 3.0.0 (Python)
- **Database**: SQLite with SQLAlchemy 3.1.1
- **Security**: Werkzeug 3.0.1
- **ORM**: Flask-SQLAlchemy
- **Frontend**: HTML5, CSS3 with custom styling
- **UI/UX**: Modern gradient design, responsive layout, animated popups

## Project Structure

```
Python-Login-Page/
├── app.py                  # Main Flask application
├── requirements.txt        # Project dependencies
├── instance/              # Instance folder
│   └── users.db          # SQLite database
├── templates/             # HTML templates
│   ├── login.html        # Login page with popup notification
│   ├── register.html     # Registration page with validation
│   ├── congrats.html     # Congratulations page after login
│   ├── dashboard.html    # User dashboard
│   └── profile.html      # User profile
├── static/               # Static files (currently empty)
└── README.md            # Project documentation
```

## Screenshots

### Login Page
- Modern gradient design (purple theme)
- Form validation
- Success popup notifications for new registrations

### Registration Page
- Username, email, password fields
- Password confirmation
- Real-time validation
- Error messages for validation failures

### Congratulations Page
- Animated success icon
- User information display
- Quick navigation buttons to dashboard and profile

### Dashboard
- Personalized welcome message
- Account information display
- Quick stats overview
- Navigation to profile and logout

## License

MIT License

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## Author

Abdulwahab A. Alessa

## Acknowledgments

- Flask framework for the backend
- SQLAlchemy for database management
- Werkzeug for password security
