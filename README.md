Secure Authentication System
Table of Contents
Introduction
Features
Technologies Used
System Architecture
Key Files
Security Implementation
Setup Instructions
Testing
Assignment Context
Future Improvements
Author
License
1. Introduction

This project is a secure web-based authentication system developed for the CET324 Advanced CyberSecurity module. It demonstrates the implementation of secure registration and login mechanisms with additional security layers such as CAPTCHA, OTP verification, Two-Factor Authentication, and activity logging. The system is designed using defence-in-depth principles to protect against common web-based attacks.

2. Features
Authentication and Security
User registration and login
Password strength validation
Password hashing using bcrypt
SQL injection protection using prepared statements
Session management and regeneration
Bot Protection
Cloudflare Turnstile CAPTCHA
Server-side CAPTCHA verification
Email Verification and Recovery
Email OTP verification using secure random generation
Forgot password functionality with secure token
Password reset with validation rules
Password history and expiry enforcement
Two-Factor Authentication
TOTP-based authentication (Google Authenticator compatible)
QR code setup
Secondary verification during login
Backup and Monitoring
Secure backup codes using cryptographic randomness
One-time use backup codes
Activity logging for security events
Failed login tracking and account lockout
OTP attempt limiting with cooldown
3. Technologies Used
Backend: PHP
Database: MySQL
Frontend: HTML, CSS, JavaScript
Libraries and Tools:
PHPMailer
Google Authenticator (TOTP)
Cloudflare Turnstile CAPTCHA
4. System Architecture

The system follows a modular web architecture:

User → Frontend (HTML, CSS, JavaScript)
→ Backend (PHP)
→ Database (MySQL)

Security layers include input validation, CAPTCHA verification, password hashing, OTP verification, and Two-Factor Authentication.

5. Key Files
File	Description
register.php	Handles registration, password validation, CAPTCHA, and OTP
login.php	Handles authentication, sessions, and brute-force protection
verify_otp.php	Verifies email OTP with attempt limiting
forgot_password.php	Generates secure password reset token
reset_password.php	Handles password update and validation
verify_2fa_setup.php	Verifies 2FA setup
verify_login_2fa.php	Verifies 2FA during login
generate_backup_codes.php	Generates secure backup codes
db.php	Database connection and activity logging
6. Security Implementation

The system applies multiple layers of security:

bcrypt hashing for password storage
random_int and random_bytes for secure randomness
prepared statements to prevent SQL injection
CAPTCHA to prevent automated attacks
OTP verification with attempt limiting
Two-Factor Authentication for additional security
backup codes for recovery
activity logging for monitoring
7. Setup Instructions
Clone the Repository

git clone https://github.com/AashutoshRegmi/acs.git

Move to Server Directory

Place the project in:

htdocs (XAMPP) or
www (WAMP)
Database Setup
Start MySQL server
The database and tables are automatically created on first run via db.php
Configuration

Update the following:

Database credentials in db.php
Email configuration in PHPMailer
Cloudflare Turnstile site key and secret key
Run the Application

http://localhost/acs

8. Testing

The system has been tested for:

Password strength validation
CAPTCHA verification
SQL injection protection
OTP verification and expiry
Two-Factor Authentication setup and login
Backup code functionality
Email delivery
System performance
9. Assignment Context

This project was developed for the CET324 Advanced CyberSecurity module at the University of Sunderland. It meets the requirements of secure system design, password strength evaluation, CAPTCHA implementation, and security testing.

10. Future Improvements
Encrypt 2FA secrets in the database
Improve user interface design
Enforce HTTPS for secure communication
Implement role-based access control
Improve centralized error handling
11. Author

Aashutosh Regmi
BSc IT Student

12. License

This project is developed for academic purposes only.
