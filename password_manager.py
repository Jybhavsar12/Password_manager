import bcrypt
import os
import tkinter as tk
from tkinter import messagebox

PASSWORD_FILE = "passwords.txt"

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def save_password(username: str, hashed_password: bytes):
    with open(PASSWORD_FILE, "a") as f:
        f.write(f"{username}:{hashed_password.decode()}\n")

def verify_password(username: str, password: str) -> bool:
    if not os.path.exists(PASSWORD_FILE):
        return False
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            stored_user, stored_hash = line.strip().split(":")
            if stored_user == username:
                return bcrypt.checkpw(password.encode(), stored_hash.encode())
    return False

def create_user():
    username = entry_username.get()
    password = entry_password.get()
    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return
    hashed = hash_password(password)
    save_password(username, hashed)
    messagebox.showinfo("Success", f"User '{username}' created successfully.")
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)

def verify_user():
    username = entry_username.get()
    password = entry_password.get()
    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return
    if verify_password(username, password):
        messagebox.showinfo("Success", "Password verified successfully!")
    else:
        messagebox.showerror("Failure", "Invalid username or password.")
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)

# GUI Setup
root = tk.Tk()
root.title("Simple Password Manager")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

label_username = tk.Label(frame, text="Username:")
label_username.grid(row=0, column=0, sticky="e")
entry_username = tk.Entry(frame)
entry_username.grid(row=0, column=1)

label_password = tk.Label(frame, text="Password:")
label_password.grid(row=1, column=0, sticky="e")
entry_password = tk.Entry(frame, show="*")
entry_password.grid(row=1, column=1)

btn_create = tk.Button(frame, text="Create User", command=create_user)
btn_create.grid(row=2, column=0, pady=10)

btn_verify = tk.Button(frame, text="Verify User", command=verify_user)
btn_verify.grid(row=2, column=1, pady=10)

root.mainloop()
