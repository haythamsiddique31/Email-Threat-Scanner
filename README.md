# Email Threat Scanner

A lightweight, educational Python tool for analyzing email content and detecting behavioural indicators of malicious intent. Designed for blue-team training, security awareness, and malware analysis education.

## What It Detects 
# Doesn't affect anything external - def not excluding

| Category | Description | Example |
|----------|-------------|---------|
| **Quid Pro Quo** | Social engineering where attacker offers help in exchange for access/credentials | "I'm from IT support. Let me fix your computer remotely." |
| **Trojan Delivery** | Attempts to deliver malware via attachments or embedded scripts | `.exe` attachments, password-protected archives, double extensions |
| **Phishing** | Credential harvesting and deceptive sender practices | Spoofed display names, mismatched reply-to, URL shorteners |

## Installation - How to set up + use

```bash
git clone https://github.com/YOUR_USERNAME/email-threat-scanner.git
cd email-threat-scanner
pip install -r requirements.txt # IF YOU HAVE LATEST VERSION OF PYTHON INSTALLED
