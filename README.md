
# SecureShare

SecureShare is a robust, secure file-sharing platform designed to facilitate encrypted file uploads, sharing, and downloads. It offers advanced security features, including user authentication, encryption, and customizable sharing options such as password protection, download limits, and expiration dates.

---

## Features

- **User Authentication**: Secure login and registration system with bcrypt password hashing.
- **File Encryption**: Ensures files are encrypted before storage using the Fernet symmetric encryption.
- **Secure Sharing**: Generate shareable links with optional password protection.
- **Access Control**: Define expiration dates and download limits for shared files.
- **Modern UI**: User-friendly, responsive interface built with Bootstrap.
- **CSRF Protection**: Safeguards against Cross-Site Request Forgery attacks.
- **Session Management**: Encrypted cookies ensure secure user sessions.

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Pip (Python package manager)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-share.git
   cd secure-share
   ```

2. Set up a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```bash
   flask shell
   >>> from app import db
   >>> db.create_all()
   >>> exit()
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Open the app in your browser: [http://localhost:5000](http://localhost:5000)

---

## Usage

### 1. **Register or Login**
   - Register for a new account or log in using existing credentials.
   - Passwords are securely hashed before storage.

### 2. **Upload Files**
   - Use the "Upload File" button to securely upload files.
   - Files are encrypted before being stored on the server.

### 3. **Share Files**
   - Click the "Share" button next to any file to create a shareable link.
   - Configure additional options:
     - **Expiration Date**: Set a date after which the link will expire.
     - **Download Limit**: Restrict the number of times the file can be downloaded.
     - **Password**: Protect access to the file with a password.

### 4. **Download Files**
   - Use the shared link to download files securely.
   - Enter the password if required.

### 5. **Logout**
   - Log out to securely end your session.

---

## Directory Structure

```
secure-share/
├── app.py                  # Main application file
├── requirements.txt        # Project dependencies
├── uploads/                # Storage directory for uploaded files (auto-created)
├── templates/              # HTML templates for the app
│   ├── index.html          # Login and registration page
│   ├── dashboard.html      # User dashboard
│   └── share_auth.html     # Password prompt for shared links
└── README.md               # This file
```

---

## Configuration

The application uses the following environment variables (auto-generated if not provided):

- `SECRET_KEY`: For session management and CSRF protection.
- `ENCRYPTION_KEY`: To encrypt files.

If these variables are not set, the application will auto-generate and save them locally.

---

## Dependencies

- **Flask**: Web framework for Python.
- **Flask-WTF**: Provides form handling and CSRF protection.
- **Flask-SQLAlchemy**: Database ORM for managing data models.
- **Cryptography**: Used for encrypting files.
- **Bcrypt**: For secure password hashing.
- **Bootstrap**: For responsive front-end design.

---

## Contributing

We welcome contributions! Follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or fix:  
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:  
   ```bash
   git commit -m "Add a brief description of your change"
   ```
4. Push the changes to your branch:  
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a pull request on GitHub.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<!-- ## Screenshots

### Login Page
![Login Page](screenshots/login.png)

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Share Modal
![Share Modal](screenshots/share-modal.png)

--- -->

## Author

- GitHub: [@4LPH7](https://github.com/4LPH7)

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/yourusername/secure-share/issues).

Feel free to contribute or suggest improvements!

---
### Show your support

Give a ⭐ if you like this website!

<a href="https://buymeacoffee.com/arulartadg" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-violet.png" alt="Buy Me A Coffee" height= "60px" width= "217px" ></a>
