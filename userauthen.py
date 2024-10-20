import hashlib
import secrets
import getpass

# Dictionary to store user credentials
user_data = {}

def hash_password(password, salt):
    """Generate a SHA-256 hash for a given password and salt."""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def register_user():
    """Register a new user by storing their username, salt, and hashed password."""
    print("\n--- Register ---")
    username = input("Create a username: ")
    if username in user_data:
        print("Username already exists. Try a different one.")
        return

    password = getpass.getpass("Create a password: ")
    if len(password) < 6:
        print("Password too short. It should be at least 6 characters.")
        return

    salt = secrets.token_hex(16)
    hashed_password = hash_password(password, salt)
    user_data[username] = {'salt': salt, 'hashed_password': hashed_password}
    print("User registered successfully!\n")

def login_user():
    """Log in an existing user by verifying their password."""
    print("\n--- Login ---")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    if username in user_data:
        stored_data = user_data[username]
        hashed_password = hash_password(password, stored_data['salt'])
        
        if hashed_password == stored_data['hashed_password']:
            print("Login successful!")
            access_secured_page()
            return
    print("Invalid username or password.\n")

def access_secured_page():
    """Access a secured area after successful login."""
    print("\n--- Secured Page ---")
    print("Welcome to the secured area! You have been selected!")
    print("-------------------------\n")

def main_menu():
    """Main menu for user interaction."""
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")
        
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

# Run the main menu
main_menu()
