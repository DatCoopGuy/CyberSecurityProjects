import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog

password_manager = {"admin": hashlib.sha256("123".encode()).hexdigest()}

def create_account():
    username = simpledialog.askstring("Create Account", "Enter a username:")
    if username is None:
        return  # Do nothing if cancel is pressed
    if not username or username in password_manager:
        messagebox.showerror("Error", "Username already exists or invalid!")
        return
    password = simpledialog.askstring("Create Account", "Enter a password:", show="*")
    if password is None:
        return  # Do nothing if cancel is pressed
    password_manager[username] = hashlib.sha256(password.encode()).hexdigest()
    messagebox.showinfo("Success", "Account created successfully!")

def login():
    username = entry_username.get()
    password = entry_password.get()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if username in password_manager and password_manager[username] == hashed_password:
        messagebox.showinfo("Login Successful", f"Welcome {username}!")
        if username == "admin":
            admin_menu()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

def admin_menu():
    root.withdraw()  # Hide the main login window
    admin_window = tk.Toplevel(root)
    admin_window.title("Admin Menu")
    admin_window.geometry("300x150")  # Set default window size
    tk.Label(admin_window, text="Admin Menu", font=("Arial", 14)).pack()
    tk.Button(admin_window, text="View Users", command=view_users).pack()
    tk.Button(admin_window, text="Change Password", command=change_password).pack()
    tk.Button(admin_window, text="Delete User", command=delete_user).pack()
    tk.Button(admin_window, text="Return to Login", command=lambda: return_to_login(admin_window)).pack()
def return_to_login(admin_window):
        admin_window.destroy()
        root.deiconify()  # Show the main login window again

def view_users():
    users = "\n".join(password_manager.keys())
    messagebox.showinfo("Users", users)

def change_password():
    username = simpledialog.askstring("Change Password", "Enter username:")
    if username is None:
        return  # Do nothing if cancel is pressed
    if username in password_manager and username != "admin":
        new_password = simpledialog.askstring("Change Password", "Enter new password:", show="*")
        if new_password is None:
            return  # Do nothing if cancel is pressed
        password_manager[username] = hashlib.sha256(new_password.encode()).hexdigest()
        messagebox.showinfo("Success", "Password updated successfully!")
    else:
        messagebox.showerror("Error", "Invalid username or admin password change denied!")

def delete_user():
    username = simpledialog.askstring("Delete User", "Enter username:")
    if username is None:
        return  # Do nothing if cancel is pressed
    if username in password_manager and username != "admin":
        del password_manager[username]
        messagebox.showinfo("Success", "User deleted successfully!")
    else:
        messagebox.showerror("Error", "Invalid username or cannot delete admin!")


# GUI Setup
root = tk.Tk()
root.title("E Corp Login Portal")
root.geometry("280x170")  # Set default window size

tk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=10)
entry_username = tk.Entry(root)
entry_username.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
entry_password = tk.Entry(root, show="*")
entry_password.grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Login", command=login).grid(row=2, column=0, columnspan=2, pady=10)
tk.Button(root, text="Create Account", command=create_account).grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()