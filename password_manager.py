import tkinter as tk
from tkinter import messagebox
import sqlite3
from cryptography.fernet import Fernet
import hashlib

# Database setup
conn = sqlite3.connect('password_manager.db')
c = conn.cursor()

# Create tables if not exists
c.execute('''
CREATE TABLE IF NOT EXISTS master_password (
    id INTEGER PRIMARY KEY,
    password_hash TEXT NOT NULL
)
''')

c.execute('''
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    website TEXT NOT NULL,
    encrypted_password TEXT NOT NULL
)
''')

conn.commit()

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Functions for the app
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_master_password(master_password):
    hashed_password = hash_password(master_password)
    c.execute('INSERT INTO master_password (password_hash) VALUES (?)', (hashed_password,))
    conn.commit()

def authenticate_master_password(master_password):
    hashed_password = hash_password(master_password)
    c.execute('SELECT * FROM master_password WHERE password_hash = ?', (hashed_password,))
    return c.fetchone() is not None

def save_password(username, website, password):
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    c.execute('INSERT INTO passwords (username, website, encrypted_password) VALUES (?, ?, ?)', 
              (username, website, encrypted_password))
    conn.commit()

def retrieve_password(website):
    c.execute('SELECT username, encrypted_password FROM passwords WHERE website = ?', (website,))
    result = c.fetchone()
    if result:
        username, encrypted_password = result
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        return username, decrypted_password
    return None

# GUI setup
def setup_master_password():
    def save():
        master_password = master_password_entry.get()
        confirm_password = confirm_password_entry.get()
        if master_password == confirm_password:
            save_master_password(master_password)
            messagebox.showinfo('Success', 'Master password set successfully!')
            setup_window.destroy()
            main_window()
        else:
            messagebox.showerror('Error', 'Passwords do not match')
    
    setup_window = tk.Tk()
    setup_window.title('Setup Master Password')

    tk.Label(setup_window, text='Master Password:').pack()
    master_password_entry = tk.Entry(setup_window, show='*')
    master_password_entry.pack()

    tk.Label(setup_window, text='Confirm Password:').pack()
    confirm_password_entry = tk.Entry(setup_window, show='*')
    confirm_password_entry.pack()

    tk.Button(setup_window, text='Save', command=save).pack()
    setup_window.mainloop()

def main_window():
    def authenticate():
        master_password = master_password_entry.get()
        if authenticate_master_password(master_password):
            messagebox.showinfo('Success', 'Authentication successful!')
            master_password_window.destroy()
            password_manager()
        else:
            messagebox.showerror('Error', 'Incorrect master password')

    master_password_window = tk.Tk()
    master_password_window.title('Enter Master Password')

    tk.Label(master_password_window, text='Master Password:').pack()
    master_password_entry = tk.Entry(master_password_window, show='*')
    master_password_entry.pack()

    tk.Button(master_password_window, text='Authenticate', command=authenticate).pack()
    master_password_window.mainloop()

def password_manager():
    def save():
        username = username_entry.get()
        website = website_entry.get()
        password = password_entry.get()
        save_password(username, website, password)
        messagebox.showinfo('Success', 'Password saved successfully!')

    def retrieve():
        website = website_entry.get()
        result = retrieve_password(website)
        if result:
            username, password = result
            messagebox.showinfo('Password Retrieved', f'Username: {username}\nPassword: {password}')
        else:
            messagebox.showerror('Error', 'No password found for this website')

    manager_window = tk.Tk()
    manager_window.title('Password Manager')

    tk.Label(manager_window, text='Username:').pack()
    username_entry = tk.Entry(manager_window)
    username_entry.pack()

    tk.Label(manager_window, text='Website:').pack()
    website_entry = tk.Entry(manager_window)
    website_entry.pack()

    tk.Label(manager_window, text='Password:').pack()
    password_entry = tk.Entry(manager_window, show='*')
    password_entry.pack()

    tk.Button(manager_window, text='Save Password', command=save).pack()
    tk.Button(manager_window, text='Retrieve Password', command=retrieve).pack()
    manager_window.mainloop()

# Check if master password is set
c.execute('SELECT * FROM master_password')
if c.fetchone() is None:
    setup_master_password()
else:
    main_window()
