
import flet as ft
import requests
import time

BASE_URL = "http://127.0.0.1:5000/api"

def main(page: ft.Page):
    page.title = "Secure Login App"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.padding = 20
    page.window_width = 400
    page.window_height = 800

    # --- STATE ---
    user_data = None
    
    # --- UI COMPONENTS ---
    
    # Common
    def show_snack(message, color=ft.colors.RED):
        page.snack_bar = ft.SnackBar(content=ft.Text(message), bgcolor=color)
        page.snack_bar.open = True
        page.update()

    # --- VIEWS ---

    # 1. Login View
    def login_view():
        username_field = ft.TextField(label="Username", width=300)
        password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=300)
        
        def handle_login(e):
            if not username_field.value or not password_field.value:
                show_snack("Please fill all fields")
                return

            try:
                res = requests.post(f"{BASE_URL}/login", json={
                    "username": username_field.value,
                    "password": password_field.value
                })
                
                if res.status_code == 200:
                    data = res.json()
                    nonlocal user_data
                    user_data = data['user']
                    page.go("/dashboard")
                elif res.status_code == 202:
                    # 2FA Required
                    data = res.json()
                    page.go(f"/verify-2fa/{data['user_id']}")
                else:
                    show_snack(res.json().get('error', 'Login failed'))
            except Exception as ex:
                show_snack(f"Connection error: {ex}")

        return ft.View(
            "/login",
            controls=[
                ft.Text("Welcome Back", size=30, weight=ft.FontWeight.BOLD),
                ft.SizedBox(height=20),
                username_field,
                ft.SizedBox(height=10),
                password_field,
                ft.SizedBox(height=20),
                ft.ElevatedButton("Login", on_click=handle_login, width=300),
                ft.TextButton("Create Account", on_click=lambda _: page.go("/register"))
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

    # 2. Register View
    def register_view():
        username_field = ft.TextField(label="Username", width=300)
        email_field = ft.TextField(label="Email", width=300)
        password_field = ft.TextField(label="Password", password=True, width=300)
        
        def handle_register(e):
            if not username_field.value or not email_field.value or not password_field.value:
                show_snack("Please fill all fields")
                return

            try:
                res = requests.post(f"{BASE_URL}/register", json={
                    "username": username_field.value,
                    "email": email_field.value,
                    "password": password_field.value
                })
                
                if res.status_code == 201:
                    show_snack("Registration successful! Please login.", ft.colors.GREEN)
                    page.go("/login")
                else:
                    show_snack(res.json().get('error', 'Registration failed'))
            except Exception as ex:
                show_snack(f"Connection error: {ex}")

        return ft.View(
            "/register",
            controls=[
                ft.Text("Create Account", size=30, weight=ft.FontWeight.BOLD),
                ft.SizedBox(height=20),
                username_field,
                ft.SizedBox(height=10),
                email_field,
                ft.SizedBox(height=10),
                password_field,
                ft.SizedBox(height=20),
                ft.ElevatedButton("Register", on_click=handle_register, width=300),
                ft.TextButton("Already have an account? Login", on_click=lambda _: page.go("/login"))
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

    # 3. 2FA Verification View
    def verify_2fa_view(user_id):
        token_field = ft.TextField(label="2FA Token", width=300, text_align=ft.TextAlign.CENTER)
        
        def handle_verify(e):
            try:
                res = requests.post(f"{BASE_URL}/verify-2fa", json={
                    "user_id": int(user_id),
                    "token": token_field.value
                })
                
                if res.status_code == 200:
                    data = res.json()
                    nonlocal user_data
                    user_data = data['user']
                    page.go("/dashboard")
                else:
                    show_snack(res.json().get('error', 'Verification failed'))
            except Exception as ex:
                show_snack(f"Connection error: {ex}")

        return ft.View(
            f"/verify-2fa/{user_id}",
            controls=[
                ft.Text("Two-Factor Auth", size=30, weight=ft.FontWeight.BOLD),
                ft.Text("Enter code from Authenticator", size=16),
                ft.SizedBox(height=20),
                token_field,
                ft.SizedBox(height=20),
                ft.ElevatedButton("Verify", on_click=handle_verify, width=300),
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

    # 4. Dashboard View
    def dashboard_view():
        if not user_data:
            page.go("/login")
            return ft.View("/dashboard", controls=[])

        return ft.View(
            "/dashboard",
            controls=[
                ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN, size=60),
                ft.Text(f"Welcome, {user_data['username']}!", size=24, weight=ft.FontWeight.BOLD),
                ft.Text(f"Email: {user_data['email']}", size=16),
                ft.SizedBox(height=40),
                ft.ElevatedButton("Logout", on_click=lambda _: page.go("/login"), width=200, bgcolor=ft.colors.RED_400, color=ft.colors.WHITE)
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

    # --- ROUTING ---
    def route_change(e):
        page.views.clear()
        
        if page.route == "/login":
            page.views.append(login_view())
        elif page.route == "/register":
            page.views.append(register_view())
        elif page.route == "/dashboard":
            page.views.append(dashboard_view())
        elif page.route.startswith("/verify-2fa"):
            user_id = page.route.split("/")[-1]
            page.views.append(verify_2fa_view(user_id))
        else:
            page.views.append(login_view()) # Default
            
        page.update()

    def view_pop(e):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)

    page.on_route_change = route_change
    page.on_view_pop = view_pop
    
    page.go("/login")

ft.app(target=main)
