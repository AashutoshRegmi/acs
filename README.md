# SecureAuth - Educational Authentication System

![SecureAuth Logo](img/logo.png)

An educational implementation of a user authentication system featuring premium black & gold theming, two-factor authentication (2FA), and contemporary security patterns. This project demonstrates authentication best practices including CSRF protection, session management, and multi-factor authentication.

> **Educational Purpose**: This is a coursework/learning project demonstrating authentication security concepts. While it incorporates industry-standard practices (bcrypt hashing, 2FA, CSRF tokens, prepared statements), it has not undergone professional security audits or hardened deployment processes required for production systems handling sensitive user data. Do not use in production without comprehensive security review and penetration testing.

## Features

### Core Authentication
- **Secure Registration** with email verification
- **Multi-factor Authentication** (2FA) with Google Authenticator
- **Backup Codes** for 2FA recovery
- **Password Reset** with secure token system
- **Session Management** with automatic logout
- **Account Lockout** after failed login attempts

### Premium UI/UX
- **Black & Gold Theme** with glassmorphism effects
- **Responsive Design** optimized for all devices
- **Font Awesome Icons** with gold theming
- **Smooth Animations** and micro-interactions
- **Accessibility Compliant** design

### Security Features
- **Password History** prevents reuse of old passwords
- **Rate Limiting** on login attempts
- **IP Tracking** and activity logging
- **CSRF Protection** on forms
- **SQL Injection Prevention** with prepared statements
- **XSS Protection** with input sanitization
- **Secure Password Hashing** with bcrypt
- **Email Verification** prevents fake accounts

### Communication
- **PHPMailer Integration** for reliable email delivery
- **SMTP Configuration** for Gmail and other providers
- **OTP Verification** for critical operations
- **Email Change Verification** with security codes

### Monitoring & Analytics
- **Activity Logging** for all user actions
- **Login History** with IP and device tracking
- **Security Dashboard** for administrators
- **Real-time Notifications** for suspicious activities

## Technologies Used

### Backend
- **PHP 8.0+** with PDO for database operations
- **MySQL 8.0+** for data storage
- **PHPMailer** for email functionality
- **Google Authenticator** for 2FA

### Frontend
- **HTML5** with semantic markup
- **CSS3** with custom properties and animations
- **JavaScript (ES6+)** for interactive features
- **Bootstrap 5.3.0** for responsive components
- **Font Awesome 6.0** for icons

### Security & Tools
- **Composer** for dependency management
- **bcrypt** for password hashing
- **JWT-like tokens** for secure operations
- **Cloudflare Turnstile** CAPTCHA integration

## Prerequisites

- **Web Server**: Apache/Nginx with PHP support
- **PHP**: Version 8.0 or higher
- **MySQL**: Version 8.0 or higher
- **Composer**: For dependency management
- **Gmail Account**: For email functionality (or configure alternative SMTP)

## Installation & Setup

### 1. Environment Setup
```bash
# Clone or download the project to your web server root
# For XAMPP: C:\xampp\htdocs\asc\
# For WAMP: C:\wamp\www\asc\
```

### 2. Install Dependencies
```bash
cd /path/to/asc
composer install
```

### 3. Database Configuration
The application automatically creates the database and tables on first run. Ensure MySQL is running and accessible.

### 4. Environment Configuration
Create your environment file and configure secrets there:
```bash
cp .env.example .env
```

Update `.env` with your values:
```env
# App
APP_NAME=SecureAuth
APP_URL=http://your-local-or-production-url

# Database
DB_HOST=your-db-host
DB_PORT=3306
DB_NAME=your-db-name
DB_USER=your-db-user
DB_PASS=your-db-password

# SMTP
SMTP_HOST=your-smtp-host
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
FROM_EMAIL=your-from-email
FROM_NAME=SecureAuth

# Cloudflare Turnstile
TURNSTILE_SITE_KEY=your-turnstile-site-key
TURNSTILE_SECRET_KEY=your-turnstile-secret-key
```

### 5. Web Server Configuration
- Ensure `mod_rewrite` is enabled (for Apache)
- Set document root to the project directory
- Configure PHP settings for email functionality

### 6. Access the Application
```
Open the URL configured in APP_URL
```

## Configuration

### Database Settings
Configured via `.env`:
- `DB_HOST`
- `DB_PORT`
- `DB_NAME` (auto-created if it does not exist)
- `DB_USER`
- `DB_PASS`

### Security Settings
- **Password Requirements**: Minimum 8 characters, mixed case, numbers, symbols
- **Login Attempts**: 5 failed attempts trigger account lockout
- **Session Timeout**: 30 minutes of inactivity
- **Token Expiry**: 24 hours for password reset tokens

## Usage

### User Registration
1. Visit the registration page
2. Fill in required information (name, email, phone, password)
3. Complete CAPTCHA verification
4. Check email for verification link
5. Set up 2FA (recommended)

### User Login
1. Enter email/username and password
2. If 2FA enabled, enter authenticator code
3. Access dashboard upon successful authentication

### Two-Factor Authentication
1. Go to profile settings
2. Enable 2FA and scan QR code with Google Authenticator
3. Save backup codes securely
4. Use codes for additional security layer

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    middle_name VARCHAR(100) NULL,
    last_name VARCHAR(100) NOT NULL,
    country_code VARCHAR(10) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    token VARCHAR(64) NULL,
    otp VARCHAR(6) NULL,
    otp_expires TIMESTAMP NULL,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    last_ip VARCHAR(45) NULL,
    twofa_secret VARCHAR(32) NULL,
    twofa_enabled TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Additional Tables
- `password_history` - Tracks password changes
- `password_reset_tokens` - Manages password reset requests
- `twofa_backup_codes` - Stores 2FA recovery codes
- `activity_logs` - Records all user activities

## Project Structure

```
asc/
├── index.html              # Landing page
├── login.html              # Login interface
├── register.html           # Registration form
├── dashboard.html          # User dashboard
├── change_password.html    # Password change form
├── forgot_password.html    # Password recovery
├── two_factor_auth.html    # 2FA setup page
├── edit_profile.html       # Profile editing
├── activity_log.html       # User activity view
├── verify_otp.html         # OTP verification
├── *.php                   # Backend processing files
├── style.css               # Main stylesheet
├── script.js               # Client-side JavaScript
├── email_config.php        # Email configuration
├── db.php                  # Database setup & connection
├── vendor/                 # Composer dependencies
├── img/                    # Static images
└── README.md               # This file
```

## Security Implementation

This project incorporates several recognized security patterns:

- **Password Hashing**: bcrypt with automatic salt generation
- **CSRF Protection**: Token validation on state-changing endpoints
- **Session Management**: ID regeneration on authentication
- **SQL Injection Prevention**: Prepared statements with parameterized queries
- **Input Validation**: Sanitization on registration and profile updates
- **Email Verification**: OTP-based confirmation of user email
- **2FA**: Google Authenticator TOTP with backup codes
- **Rate Limiting**: Login attempt throttling
- **Activity Logging**: Audit trail of user actions

## Limitations & Deployment Considerations

**This is an educational project and has the following limitations:**

- **Not security audited** - No professional penetration testing conducted
- **Not hardened for production** - Lacks enterprise-grade deployment safeguards (TLS enforcement, WAF configuration, DDoS mitigation)
- **Development environment focus** - Designed for XAMPP/local testing, not production servers
- **Incomplete attack surface testing** - May contain untested edge cases or vulnerabilities
- **No compliance certifications** - Does not meet banking, PCI-DSS, or GDPR compliance requirements
- **Educational scope** - Suitable for demonstrating concepts; not for protecting real user data at scale

**For production use, you would need:**
- Professional security audit and penetration testing
- Additional hardening (HTTPS enforcement, security headers, rate limiting at CDN level)
- Compliance review (GDPR, CCPA, PCI-DSS as applicable)
- Monitoring and incident response infrastructure
- Regular security updates and patching process
- Legal review and terms of service/privacy policy

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Bootstrap** for responsive framework
- **Font Awesome** for icon library
- **Google Authenticator** for 2FA implementation
- **PHPMailer** for email functionality
- **Playfair Display** font for premium typography

## Support

For support, email support@secureauth.com or create an issue in the repository.

---

**SecureAuth** - Where Security Meets Elegance