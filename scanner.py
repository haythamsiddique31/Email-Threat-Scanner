"""
email-threat-scanner
A lightweight email analysis tool for detecting suspicious patterns
associated with quid pro quo, trojan delivery, and phishing.
"""

import re
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class ThreatIndicator:
    """Represents a single detected threat indicator."""
    category: str           # 'quid_pro_quo', 'trojan', 'phishing', 'general'
    severity: str           # 'low', 'medium', 'high', 'critical'
    description: str        # Human-readable explanation
    evidence: str           # The specific text/pattern that triggered it
    line_number: Optional[int] = None


class EmailThreatScanner:
    """
    Scans email content (headers + body) for behavioural indicators
    of malicious intent. Does NOT execute attachments or visit URLs.
    """

    # Known malicious file extensions commonly used for trojan delivery
    TROJAN_EXTENSIONS = {
        '.exe', '.scr', '.bat', '.cmd', '.sh', '.vbs', '.js',
        '.jar', '.ps1', '.wsf', '.hta', '.dll', '.zip', '.rar',
        '.7z', '.iso', '.img'
    }

    # URL shorteners frequently abused in phishing
    SUSPICIOUS_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl',
        'short.link', 'is.gd', 'buff.ly', 'rebrand.ly'
    }

    # Keywords suggesting quid pro quo (offer of help in exchange for access)
    QUID_PRO_QUO_PHRASES = [
        r'free (support|help|assistance|service)',
        r'complimentary (audit|review|check|scan)',
        r'I noticed (a problem|an issue|something wrong)',
        r'I can fix (this|that|it) for you',
        r'grant me (access|remote|control)',
        r'let me (connect|log in|access) to',
        r'technical support (calling|reaching out|contacting)',
        r'IT department.*(verify|confirm|update)',
        r'urgent.*(assistance|help).*required',
        r'won a (prize|gift|reward).*need (details|info|access)',
    ]

    # Phishing indicators in body text
    PHISHING_KEYWORDS = [
        r'verify your (account|identity|information)',
        r'confirm your (details|password|credentials)',
        r'update your (payment|billing|card)',
        r'suspended.*(account|access|service)',
        r'unusual activity.*(detected|found|spotted)',
        r'click (here|below|link).*immediately',
        r'limited time.*(act|respond|click)',
        r'password.*expir(ed|ing|es)',
        r'account.*(locked|disabled|terminated)',
        r'dear (customer|user|valued member)',
    ]

    # Spoofed sender patterns
    SPOOF_INDICATORS = [
        r'noreply@',
        r'support@.*\.(tk|ml|ga|cf|gq)',  # Free domains
        r'(security|alert|verify)@.*\.(com|net|org)',
        r'[0-9]+@',  # Numeric usernames
    ]

    def __init__(self):
        self.results: List[ThreatIndicator] = []
        self.score = 0  # Cumulative threat score (0-100)

    def _find_matches(self, text: str, patterns: List[str],
                      category: str, severity: str,
                      description_template: str) -> List[ThreatIndicator]:
        """Helper: find regex matches and return as indicators."""
        indicators = []
        lines = text.split('\n')

        for pattern in patterns:
            for i, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    indicators.append(ThreatIndicator(
                        category=category,
                        severity=severity,
                        description=description_template,
                        evidence=match.group(0),
                        line_number=i
                    ))
        return indicators

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text using regex."""
        # Basic URL regex - catches http, https, and bare domains
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(url_pattern, text)

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(email_pattern, text)

    def _check_spoofed_sender(self, from_header: str) -> List[ThreatIndicator]:
        """Check for signs of sender spoofing or suspicious from addresses."""
        indicators = []

        # Check against spoof patterns
        for pattern in self.SPOOF_INDICATORS:
            if re.search(pattern, from_header, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    category='phishing',
                    severity='high',
                    description='Suspicious sender address pattern detected',
                    evidence=from_header
                ))

        # Check for display name spoofing (e.g., "Bank Name <evil@gmail.com>")
        if '<' in from_header and '>' in from_header:
            display_name = from_header.split('<')[0].strip()
            actual_email = from_header[from_header.find(
                '<')+1:from_header.find('>')]

            # If display name looks like a domain but email doesn't match
            if '.' in display_name and not any(
                domain in actual_email.lower()
                for domain in display_name.lower().split()
            ):
                indicators.append(ThreatIndicator(
                    category='phishing',
                    severity='critical',
                    description='Possible display name spoofing: name does not match email domain',
                    evidence=f'Display: "{display_name}" | Actual: "{actual_email}"'
                ))

        return indicators

    def _check_quid_pro_quo(self, body: str) -> List[ThreatIndicator]:
        """
        Detect quid pro quo social engineering:
        Attacker offers help/service in exchange for access/credentials.
        """
        indicators = self._find_matches(
            body, self.QUID_PRO_QUO_PHRASES,
            'quid_pro_quo', 'medium',
            'Quid pro quo social engineering pattern detected'
        )

        # Additional heuristic: tech support language + request for remote access
        tech_support_terms = ['remote desktop', 'teamviewer',
                              'anydesk', 'logmein', 'screen connect']
        remote_access_terms = ['access', 'connect', 'control', 'fix', 'repair']

        body_lower = body.lower()
        has_tech = any(term in body_lower for term in tech_support_terms)
        has_remote = any(term in body_lower for term in remote_access_terms)

        if has_tech and has_remote:
            indicators.append(ThreatIndicator(
                category='quid_pro_quo',
                severity='high',
                description='Remote access tool mentioned alongside assistance offer - classic quid pro quo',
                evidence='Remote access tool + assistance language co-occurring'
            ))

        return indicators

    def _check_trojan_indicators(self, body: str, attachments: List[str]) -> List[ThreatIndicator]:
        """
        Detect trojan delivery attempts:
        Malicious attachments, embedded scripts, or executable references.
        """
        indicators = []

        # Check attachment extensions
        for attachment in attachments:
            ext = '.' + \
                attachment.split('.')[-1].lower() if '.' in attachment else ''
            if ext in self.TROJAN_EXTENSIONS:
                indicators.append(ThreatIndicator(
                    category='trojan',
                    severity='critical',
                    description=f'Potentially malicious attachment type: {ext}',
                    evidence=attachment
                ))

            # Double extension trick (e.g., invoice.pdf.exe)
            if body.lower().count('.') > 1:
                double_ext = re.search(
                    r'\.[a-zA-Z0-9]+\.[a-zA-Z0-9]{1,4}', attachment)
                if double_ext:
                    indicators.append(ThreatIndicator(
                        category='trojan',
                        severity='critical',
                        description='Double file extension - common trojan obfuscation',
                        evidence=attachment
                    ))

        # Check for embedded scripts or macros in body
        script_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'macro.*enable',
            r'content-disposition:.*attachment',
            r'base64,',
        ]

        for pattern in script_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    category='trojan',
                    severity='high',
                    description='Embedded script or encoded content detected',
                    evidence=pattern.replace(r'\w+', '...')
                ))

        # Check for password-protected archives (often used to bypass scanners)
        if re.search(r'password.*(zip|rar|7z|archive)', body, re.IGNORECASE):
            indicators.append(ThreatIndicator(
                category='trojan',
                severity='high',
                description='Password-protected archive mentioned - common evasion technique',
                evidence='Password + archive reference'
            ))

        return indicators

    def _check_phishing(self, body: str, headers: Dict[str, str]) -> List[ThreatIndicator]:
        """
        Detect phishing indicators:
        Credential harvesting, fake login pages, urgency manipulation.
        """
        indicators = []

        # Body text indicators
        indicators.extend(self._find_matches(
            body, self.PHISHING_KEYWORDS,
            'phishing', 'medium',
            'Phishing keyword pattern detected'
        ))

        # URL analysis
        urls = self._extract_urls(body)
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check for URL shorteners
            if any(short in domain for short in self.SUSPICIOUS_SHORTENERS):
                indicators.append(ThreatIndicator(
                    category='phishing',
                    severity='high',
                    description='URL shortener detected - frequently used to mask phishing destinations',
                    evidence=url
                ))

            # Check for IP-based URLs (e.g., http://192.168.1.1/login)
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                indicators.append(ThreatIndicator(
                    category='phishing',
                    severity='high',
                    description='IP address used instead of domain name - suspicious',
                    evidence=url
                ))

            # Check for homograph attacks (mixed scripts, lookalike chars)
            if re.search(r'[а-яА-Я]', url):  # Cyrillic chars in Latin-looking URL
                indicators.append(ThreatIndicator(
                    category='phishing',
                    severity='critical',
                    description='Possible homograph attack: non-ASCII characters in URL',
                    evidence=url
                ))

            # Misspelled brand domains (basic check)
            brand_domains = ['paypal', 'apple',
                             'microsoft', 'amazon', 'google', 'facebook']
            for brand in brand_domains:
                # Levenshtein distance of 1 (e.g., paypa1, micr0soft)
                if brand in domain and domain != brand and domain != f'www.{brand}.com':
                    if len(domain) - len(brand) <= 2:
                        indicators.append(ThreatIndicator(
                            category='phishing',
                            severity='high',
                            description=f'Possible typosquatting of {brand}',
                            evidence=url
                        ))

        # Check for form submission targets
        if re.search(r'<form[^>]*action=', body, re.IGNORECASE):
            indicators.append(ThreatIndicator(
                category='phishing',
                severity='medium',
                description='HTML form detected - potential credential harvesting',
                evidence='Form element with action attribute'
            ))

        # Check reply-to mismatch
        from_addr = headers.get('From', '')
        reply_to = headers.get('Reply-To', '')
        if reply_to and reply_to != from_addr:
            indicators.append(ThreatIndicator(
                category='phishing',
                severity='high',
                description='Reply-To address differs from From address - common phishing technique',
                evidence=f'From: {from_addr} | Reply-To: {reply_to}'
            ))

        return indicators

    def _calculate_score(self, indicators: List[ThreatIndicator]) -> int:
        """Calculate overall threat score based on indicators."""
        score = 0
        severity_weights = {
            'low': 5,
            'medium': 15,
            'high': 30,
            'critical': 50
        }

        for ind in indicators:
            score += severity_weights.get(ind.severity, 10)

        return min(score, 100)  # Cap at 100

    def scan(self, raw_email: str, attachments: List[str] = None) -> Dict:
        """
        Main scan method. Takes raw email string and optional attachment list.
        Returns structured analysis results.
        """
        if attachments is None:
            attachments = []

        self.results = []

        # Parse headers and body
        headers, body = self._parse_email(raw_email)

        # Run all detection modules
        self.results.extend(
            self._check_spoofed_sender(headers.get('From', '')))
        self.results.extend(self._check_quid_pro_quo(body))
        self.results.extend(self._check_trojan_indicators(body, attachments))
        self.results.extend(self._check_phishing(body, headers))

        self.score = self._calculate_score(self.results)

        return self._build_report(headers, body, attachments)

    def _parse_email(self, raw_email: str) -> Tuple[Dict[str, str], str]:
        """Parse raw email into headers dict and body string."""
        headers = {}
        body = raw_email

        # Simple header parsing (assumes standard email format)
        if '\n\n' in raw_email or '\r\n\r\n' in raw_email:
            # Try to split headers from body
            parts = raw_email.split('\n\n', 1)
            if len(parts) == 1:
                parts = raw_email.split('\r\n\r\n', 1)

            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ''

            # Parse key: value pairs
            for line in header_section.split('\n'):
                if ':' in line and not line.startswith(' '):
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

        return headers, body

    def _build_report(self, headers: Dict, body: str, attachments: List[str]) -> Dict:
        """Build final JSON report."""
        return {
            'scan_metadata': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'scanner_version': '1.0.0',
                'email_hash': hashlib.sha256(body.encode()).hexdigest()[:16]
            },
            'summary': {
                'threat_score': self.score,
                'risk_level': self._get_risk_level(self.score),
                'total_indicators': len(self.results),
                'categories_found': list(set(ind.category for ind in self.results))
            },
            'headers_analyzed': {
                'from': headers.get('From', 'Not found'),
                'to': headers.get('To', 'Not found'),
                'subject': headers.get('Subject', 'Not found'),
                'reply_to': headers.get('Reply-To', 'Not found'),
                'date': headers.get('Date', 'Not found')
            },
            'attachments_scanned': attachments,
            'indicators': [asdict(ind) for ind in self.results],
            'recommendations': self._generate_recommendations()
        }

    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return 'CRITICAL'
        if score >= 60:
            return 'HIGH'
        if score >= 40:
            return 'MEDIUM'
        if score >= 20:
            return 'LOW'
        return 'MINIMAL'

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recs = []
        categories = set(ind.category for ind in self.results)

        if 'quid_pro_quo' in categories:
            recs.append(
                'Verify unsolicited tech support offers through official channels')
            recs.append('Never grant remote access to unknown callers')

        if 'trojan' in categories:
            recs.append('Do not open attachments from untrusted sources')
            recs.append(
                'Scan all attachments with multiple AV engines before opening')
            recs.append(
                'Be suspicious of password-protected archives in emails')

        if 'phishing' in categories:
            recs.append('Verify sender identity through secondary channel')
            recs.append('Hover over links to inspect actual destinations')
            recs.append(
                'Do not enter credentials on pages reached via email links')
            recs.append(
                'Check for HTTPS and valid certificates on login pages')

        if not recs:
            recs.append(
                'No significant threats detected - standard security hygiene applies')

        return recs


def main():
    """CLI entry point for testing."""
    import sys

    print("Email Threat Scanner v1.0.0")
    print("=" * 50)

    # Demo email for testing
    test_email = """From: "Microsoft Support" <support@micros0ft-security.tk>
To: victim@company.com
Subject: URGENT: Your account has been suspended
Reply-To: helpdesk-urgent@gmail.com
Date: Mon, 13 Jul 2026 09:00:00 +0000

Dear valued customer,

We noticed unusual activity on your account. Your access has been suspended pending verification.

Please verify your information immediately by clicking below:
https://bit.ly/3xAmP1e

Our complimentary technical support team can fix this for you. Grant me remote access and I will resolve the issue immediately. Download TeamViewer from the attachment.

Password for archive: 1234

Best regards,
Microsoft Security Team"""

    attachments = ['security_update.pdf.exe', 'teamviewer_setup.zip']

    scanner = EmailThreatScanner()
    report = scanner.scan(test_email, attachments)

    print(json.dumps(report, indent=2))

    # Optionally read from file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            email_content = f.read()
        report = scanner.scan(email_content)
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
