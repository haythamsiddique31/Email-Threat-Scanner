# Email Threat Scanner

A lightweight, educational Python tool for analysing email content and detecting behavioural indicators of malicious intent. Designed for blue-team training, security awareness, and malware analysis education - anything else also but moreso those sectors - 1st iteration, will be improving this upon feedback ~

## What It Essentially Detects:

**Quid Pro Quo**: Social engineering where the attacker offers help in exchange for access/credentials, further navigation within a system | "Hey, I'm from IT support. Let me fix your computer remotely, "You just won a free Ipad, clck here for more, etc." 

**Trojan Delivery**: Attempts to deliver malware via attachments or embedded scripts, `.exe` attachments, password-protected archives, double extensions, mispelled domains

**Phishing (Including SPEAR PHISHING)**: Credential harvesting and deceptive sender practices, Spoofed display names, mismatched reply-to, URL shorteners

## Installation - Purpose & Use

```bash
git clone https://github.com/YOUR_USERNAME/email-threat-scanner.git
cd email-threat-scanner
pip install -r requirements.txt # IF YOU HAVE LATEST VERSION OF PYTHON INSTALLED
