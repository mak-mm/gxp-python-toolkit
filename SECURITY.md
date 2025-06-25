# Security Policy

## 🔒 Our Commitment

The GxP Python Toolkit takes security seriously. As a toolkit designed for regulated life sciences environments, we are committed to ensuring the security and integrity of our code and the systems that depend on it.

## 🆙 Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 1.0.x   | :white_check_mark: | Current stable release |
| 0.9.x   | :white_check_mark: | Pre-release versions |
| < 0.9   | :x:                | Development versions |

## 🚨 Reporting a Vulnerability

### Do NOT Report Security Vulnerabilities Publicly

Please **DO NOT** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### How to Report

Instead, please report security vulnerabilities via email to:

📧 **manuel.knott@curevac.com**

### What to Include

Please include as much of the following information as possible:

1. **Type of vulnerability** (e.g., SQL injection, XSS, authentication bypass)
2. **Affected component** (module, function, file)
3. **Steps to reproduce** the vulnerability
4. **Proof of concept** or exploit code (if available)
5. **Impact assessment** - what can an attacker achieve?
6. **Suggested remediation** (if you have one)
7. **Your contact information** for follow-up questions

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt within 48 hours
2. **Initial Assessment**: Within 5 business days, we will:
   - Confirm the vulnerability
   - Assess its severity
   - Provide an estimated timeline for a fix
3. **Updates**: We will keep you informed about our progress
4. **Fix Development**: We will develop and test a fix
5. **Disclosure**: We will coordinate disclosure with you

## 🛡️ Security Measures

The GxP Python Toolkit implements several security measures:

### Code Security
- Regular dependency scanning with Safety and Dependabot
- Static security analysis with Bandit
- Code review requirements for all changes
- Signed commits for releases

### Data Protection
- Encryption at rest for sensitive data
- Encryption in transit (TLS 1.2+)
- Secure password hashing (bcrypt)
- Cryptographic integrity checks for audit trails

### Access Control
- Role-based access control (RBAC)
- Azure AD integration
- Session management
- Failed login monitoring

### Compliance Features
- Immutable audit trails
- Electronic signatures with non-repudiation
- Data integrity controls (ALCOA+)
- Soft delete to prevent data loss

## 🔍 Security Best Practices

When using the GxP Python Toolkit:

### 1. Keep Dependencies Updated
```bash
# Check for outdated packages
pip list --outdated

# Update all dependencies
pip install --upgrade -r requirements.txt
```

### 2. Use Environment Variables for Secrets
```python
# Good
database_url = os.environ.get('DATABASE_URL')

# Bad
database_url = "postgresql://user:password@localhost/db"
```

### 3. Enable All Security Features
```python
config = GxPConfig(
    require_mfa=True,
    require_password_complexity=True,
    session_timeout_minutes=30,
    max_login_attempts=3,
    audit_enabled=True
)
```

### 4. Regular Security Audits
- Review audit trails regularly
- Monitor failed login attempts
- Check for unusual access patterns
- Verify electronic signatures

## 🚦 Security Checklist

Before deploying to production:

- [ ] All dependencies are up to date
- [ ] Security scanning completed (Safety, Bandit)
- [ ] Secrets stored securely (not in code)
- [ ] HTTPS/TLS configured
- [ ] Authentication properly configured
- [ ] Audit trail enabled and tested
- [ ] Access controls configured
- [ ] Backup and recovery tested
- [ ] Security documentation complete

## 📋 Vulnerability Disclosure Policy

We follow responsible disclosure practices:

1. **Reporters** should:
   - Allow reasonable time for fixes (typically 90 days)
   - Work with us on disclosure timing
   - Not exploit vulnerabilities beyond POC

2. **We will**:
   - Fix vulnerabilities promptly
   - Credit researchers (unless anonymity requested)
   - Publish security advisories when appropriate
   - Never pursue legal action against good-faith researchers

## 🏆 Security Hall of Fame

We gratefully acknowledge security researchers who have helped improve our security:

- *Your name could be here!*

## 📚 Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [FDA Cybersecurity Guidelines](https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity)

## 📞 Contact

- Email: manuel.knott@curevac.com

---

Thank you for helping keep the GxP Python Toolkit and its users safe! 🙏
