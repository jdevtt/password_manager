# Password Manager

A simple password manager application built with Python to  store and manage passwords using a master password for authentication. The application uses SQLite for storing passwords and the `cryptography` library for encryption.

![image](https://github.com/user-attachments/assets/720e1dcb-fccf-46b5-81c9-ff7267d6a5e4)

## Features

- Secure storage of passwords with encryption.
- User-friendly graphical interface using Tkinter.
- Master password authentication for accessing the password manager.
- Save and retrieve passwords based on username and website.

![image](https://github.com/user-attachments/assets/68b7d128-f41c-4cd0-8582-fb70634cd5c7)

## Prerequisites

- Python 3.6 or higher
- Required packages: `cryptography`, `sqlite3` and `tkinter`

## Installation

1. **Clone the repository** or download the `password_manager.py` file.

2. **Install the required packages**:
   ```sh
   pip install cryptography
   ```

## Usage

1. **Run the Application**:
   ```sh
   py password_manager.py
   ```

2. **Setup Master Password**:
   - On first run, set up a master password that will be used to authenticate and access the password manager.

3. **Authenticate**:
   - Enter the master password to access the password manager.

4. **Save Password**:
   - Enter the username, website, and password, then click "Save Password" to store the password securely.

5. **Retrieve Password**:
   - Enter the website and click "Retrieve Password" to fetch the stored username and password for the specified website.

## Code Overview

### Database Setup

The application uses SQLite to store the master password and encrypted passwords.

```python
import sqlite3

conn = sqlite3.connect('password_manager.db')
c = conn.cursor()

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
```

### Password Hashing and Encryption

The master password is hashed using SHA-256, and passwords are encrypted using Fernet symmetric encryption.

```python
import hashlib
from cryptography.fernet import Fernet

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

key = Fernet.generate_key()
cipher_suite = Fernet(key)
```

### Functions for Saving and Retrieving Passwords

Functions to save and retrieve passwords with encryption and decryption.

```python
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
```

### Graphical User Interface

The application uses Tkinter to create a GUI for setting the master password, authenticating, and managing passwords.




## License

This project is licensed under the MIT License.
