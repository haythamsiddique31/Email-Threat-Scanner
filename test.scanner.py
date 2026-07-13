"""
Unit tests for the Email Threat Scanner.
Run with: python -m pytest test_scanner.py -v
"""

import pytest
from scanner import EmailThreatScanner, ThreatIndicator


class TestQuidProQuoDetection:
    """Tests for quid pro quo social engineering detection."""
    
    def test_free_support_offer(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nI can offer free support to fix your computer."
        report = scanner.scan(email)
        assert any(ind['category'] == 'quid_pro_quo' for ind in report['indicators'])
    
    def test_remote_access_language(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nUse TeamViewer so I can connect and repair your system."
        report = scanner.scan(email)
        quid_indicators = [ind for ind in report['indicators'] if ind['category'] == 'quid_pro_quo']
        assert len(quid_indicators) > 0
        assert any('Remote access tool' in ind['description'] for ind in quid_indicators)


class TestTrojanDetection:
    """Tests for trojan delivery indicators."""
    
    def test_malicious_attachment_extension(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nPlease see attached document."
        report = scanner.scan(email, attachments=['invoice.exe'])
        assert any(ind['category'] == 'trojan' and ind['severity'] == 'critical' 
                   for ind in report['indicators'])
    
    def test_double_extension(self):
        scanner = EmailThreatScanner()
        report = scanner.scan("test", attachments=['document.pdf.exe'])
        assert any('Double file extension' in ind['description'] 
                   for ind in report['indicators'])
    
    def test_password_protected_archive(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nPassword for zip: 1234\nOpen the attachment."
        report = scanner.scan(email)
        assert any('Password-protected archive' in ind['description'] 
                   for ind in report['indicators'])


class TestPhishingDetection:
    """Tests for phishing pattern detection."""
    
    def test_spoofed_display_name(self):
        scanner = EmailThreatScanner()
        email = 'From: "PayPal" <evil@scam.com>\n\nVerify your account now.'
        report = scanner.scan(email)
        assert any('display name spoofing' in ind['description'].lower() 
                   for ind in report['indicators'])
    
    def test_url_shortener(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nClick here: https://bit.ly/abc123"
        report = scanner.scan(email)
        assert any('URL shortener' in ind['description'] 
                   for ind in report['indicators'])
    
    def test_reply_to_mismatch(self):
        scanner = EmailThreatScanner()
        email = "From: boss@company.com\nReply-To: boss@gmail.com\n\nWire money urgently."
        report = scanner.scan(email)
        assert any('Reply-To address differs' in ind['description'] 
                   for ind in report['indicators'])
    
    def test_ip_based_url(self):
        scanner = EmailThreatScanner()
        email = "From: test@example.com\n\nLogin: http://192.168.1.1/bank"
        report = scanner.scan(email)
        assert any('IP address used' in ind['description'] 
                   for ind in report['indicators'])


class TestScoring:
    """Tests for threat score calculation."""
    
    def test_critical_score(self):
        scanner = EmailThreatScanner()
        email = 'From: "Bank" <phish@evil.com>\nReply-To: steal@gmail.com\n\n'
        email += 'Verify your account: https://bit.ly/xyz\n'
        email += 'Download: update.exe\nPassword for zip: 1234'
        report = scanner.scan(email, attachments=['update.exe'])
        assert report['summary']['threat_score'] >= 60
        assert report['summary']['risk_level'] in ['HIGH', 'CRITICAL']
    
    def test_clean_email(self):
        scanner = EmailThreatScanner()
        email = "From: friend@example.com\n\nHey, want to grab lunch tomorrow?"
        report = scanner.scan(email)
        assert report['summary']['threat_score'] < 20
        assert report['summary']['risk_level'] == 'MINIMAL'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])