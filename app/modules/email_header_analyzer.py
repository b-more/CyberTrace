"""
Email Header Analyzer
CyberTrace - Zambia Police Service

Analyze email headers for forgery detection and origin tracking
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime
import socket
from typing import Dict, List, Tuple


class EmailHeaderAnalyzer:
    """Analyze email headers for forensic investigation"""

    def __init__(self):
        self.results = {
            'headers': {},
            'analysis': {},
            'authenticity': {},
            'routing': [],
            'security': {},
            'warnings': [],
            'metadata': {}
        }

    def analyze(self, headers_text: str) -> Dict:
        """
        Analyze email headers

        Args:
            headers_text (str): Raw email headers text

        Returns:
            Dict: Analysis results
        """
        # Parse headers
        msg = Parser(policy=policy.default).parsestr(headers_text)

        # Extract all headers
        self.results['headers'] = dict(msg.items())

        # Analyze components
        self._analyze_sender(msg)
        self._analyze_recipient(msg)
        self._analyze_subject(msg)
        self._analyze_dates(msg)
        self._analyze_message_id(msg)
        self._analyze_routing(msg)
        self._analyze_authentication(msg)
        self._analyze_content_type(msg)
        self._detect_forgery_indicators(msg)

        return self.results

    def _analyze_sender(self, msg):
        """Analyze sender information"""
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')

        self.results['analysis']['from'] = from_header
        self.results['analysis']['return_path'] = return_path
        self.results['analysis']['reply_to'] = reply_to

        # Extract email addresses
        from_email = self._extract_email(from_header)
        return_email = self._extract_email(return_path)

        # Check for mismatches (potential spoofing)
        if from_email and return_email and from_email != return_email:
            self.results['warnings'].append({
                'type': 'sender_mismatch',
                'severity': 'high',
                'message': f'From address ({from_email}) does not match Return-Path ({return_email})',
                'indicator': 'Potential email spoofing'
            })

        # Check Reply-To mismatch
        if reply_to and from_email:
            reply_email = self._extract_email(reply_to)
            if reply_email and reply_email != from_email:
                self.results['warnings'].append({
                    'type': 'reply_to_mismatch',
                    'severity': 'medium',
                    'message': f'Reply-To ({reply_email}) differs from From ({from_email})',
                    'indicator': 'Replies will go to different address'
                })

    def _analyze_recipient(self, msg):
        """Analyze recipient information"""
        to_header = msg.get('To', '')
        cc_header = msg.get('Cc', '')
        bcc_header = msg.get('Bcc', '')

        self.results['analysis']['to'] = to_header
        self.results['analysis']['cc'] = cc_header
        self.results['analysis']['bcc'] = bcc_header

    def _analyze_subject(self, msg):
        """Analyze subject line"""
        subject = msg.get('Subject', '')
        self.results['analysis']['subject'] = subject

        # Check for suspicious keywords
        suspicious_keywords = [
            'urgent', 'verify', 'suspend', 'confirm', 'account', 'password',
            'click here', 'act now', 'limited time', 'winner', 'prize',
            'refund', 'payment', 'invoice', 'debt'
        ]

        subject_lower = subject.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in subject_lower]

        if found_keywords:
            self.results['warnings'].append({
                'type': 'suspicious_subject',
                'severity': 'medium',
                'message': f'Subject contains suspicious keywords: {", ".join(found_keywords)}',
                'indicator': 'Common phishing tactics'
            })

    def _analyze_dates(self, msg):
        """Analyze date headers"""
        date_header = msg.get('Date', '')
        self.results['analysis']['date'] = date_header

        try:
            # Parse date
            sent_date = email.utils.parsedate_to_datetime(date_header)
            self.results['analysis']['sent_timestamp'] = sent_date.isoformat()

            # Check if date is in the future
            now = datetime.now(sent_date.tzinfo)
            if sent_date > now:
                self.results['warnings'].append({
                    'type': 'future_date',
                    'severity': 'high',
                    'message': 'Email date is in the future',
                    'indicator': 'Possible date forgery or system clock issue'
                })
        except:
            self.results['warnings'].append({
                'type': 'invalid_date',
                'severity': 'low',
                'message': 'Could not parse email date',
                'indicator': 'Malformed date header'
            })

    def _analyze_message_id(self, msg):
        """Analyze Message-ID"""
        message_id = msg.get('Message-ID', '')
        self.results['analysis']['message_id'] = message_id

        # Extract domain from Message-ID
        if message_id:
            match = re.search(r'@([\w.-]+)', message_id)
            if match:
                mid_domain = match.group(1)
                self.results['analysis']['message_id_domain'] = mid_domain

                # Compare with From domain
                from_email = self._extract_email(msg.get('From', ''))
                if from_email:
                    from_domain = from_email.split('@')[1]
                    if mid_domain.lower() != from_domain.lower():
                        self.results['warnings'].append({
                            'type': 'message_id_mismatch',
                            'severity': 'medium',
                            'message': f'Message-ID domain ({mid_domain}) differs from sender domain ({from_domain})',
                            'indicator': 'Email may have been relayed or forwarded'
                        })

    def _analyze_routing(self, msg):
        """Analyze email routing path (Received headers)"""
        received_headers = msg.get_all('Received', [])

        routing_path = []
        for i, received in enumerate(received_headers):
            hop = {
                'hop_number': i + 1,
                'header': received,
                'server': None,
                'ip': None,
                'timestamp': None
            }

            # Extract server/IP
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ip_match:
                hop['ip'] = ip_match.group(1)

            # Extract hostname
            server_match = re.search(r'from\s+([\w.-]+)', received)
            if server_match:
                hop['server'] = server_match.group(1)

            # Extract timestamp
            timestamp_match = re.search(r';\s*(.+)$', received)
            if timestamp_match:
                try:
                    hop['timestamp'] = email.utils.parsedate_to_datetime(timestamp_match.group(1)).isoformat()
                except:
                    hop['timestamp'] = timestamp_match.group(1)

            routing_path.append(hop)

        self.results['routing'] = routing_path
        self.results['analysis']['hop_count'] = len(routing_path)

        # Analyze routing anomalies
        if len(routing_path) > 10:
            self.results['warnings'].append({
                'type': 'excessive_hops',
                'severity': 'medium',
                'message': f'Email passed through {len(routing_path)} servers',
                'indicator': 'Unusually long routing path'
            })

    def _analyze_authentication(self, msg):
        """Analyze email authentication (SPF, DKIM, DMARC)"""
        auth_results = msg.get('Authentication-Results', '')

        self.results['security']['authentication_results'] = auth_results

        # Parse SPF
        if 'spf=pass' in auth_results.lower():
            self.results['security']['spf'] = 'PASS'
        elif 'spf=fail' in auth_results.lower():
            self.results['security']['spf'] = 'FAIL'
            self.results['warnings'].append({
                'type': 'spf_fail',
                'severity': 'high',
                'message': 'SPF authentication failed',
                'indicator': 'Sender is not authorized to send from this domain'
            })
        else:
            self.results['security']['spf'] = 'NONE'

        # Parse DKIM
        if 'dkim=pass' in auth_results.lower():
            self.results['security']['dkim'] = 'PASS'
        elif 'dkim=fail' in auth_results.lower():
            self.results['security']['dkim'] = 'FAIL'
            self.results['warnings'].append({
                'type': 'dkim_fail',
                'severity': 'high',
                'message': 'DKIM signature verification failed',
                'indicator': 'Email may have been tampered with'
            })
        else:
            self.results['security']['dkim'] = 'NONE'

        # Parse DMARC
        if 'dmarc=pass' in auth_results.lower():
            self.results['security']['dmarc'] = 'PASS'
        elif 'dmarc=fail' in auth_results.lower():
            self.results['security']['dmarc'] = 'FAIL'
            self.results['warnings'].append({
                'type': 'dmarc_fail',
                'severity': 'high',
                'message': 'DMARC policy check failed',
                'indicator': 'Email fails domain authentication policy'
            })
        else:
            self.results['security']['dmarc'] = 'NONE'

    def _analyze_content_type(self, msg):
        """Analyze content type and encoding"""
        content_type = msg.get('Content-Type', '')
        content_transfer_encoding = msg.get('Content-Transfer-Encoding', '')

        self.results['analysis']['content_type'] = content_type
        self.results['analysis']['content_transfer_encoding'] = content_transfer_encoding

        # Check for HTML content (phishing indicator)
        if 'text/html' in content_type.lower():
            self.results['metadata']['contains_html'] = True

        # Check for attachments
        if 'multipart' in content_type.lower():
            self.results['metadata']['has_attachments'] = True

    def _detect_forgery_indicators(self, msg):
        """Detect common email forgery indicators"""
        forgery_score = 0
        indicators = []

        # Check for missing or suspicious headers
        required_headers = ['From', 'To', 'Date', 'Message-ID']
        for header in required_headers:
            if not msg.get(header):
                forgery_score += 20
                indicators.append(f'Missing required header: {header}')

        # Count warnings
        high_severity_warnings = len([w for w in self.results['warnings'] if w.get('severity') == 'high'])
        forgery_score += high_severity_warnings * 25

        medium_severity_warnings = len([w for w in self.results['warnings'] if w.get('severity') == 'medium'])
        forgery_score += medium_severity_warnings * 10

        # Determine authenticity assessment
        if forgery_score >= 70:
            assessment = 'HIGHLY SUSPICIOUS'
            color = 'red'
        elif forgery_score >= 40:
            assessment = 'SUSPICIOUS'
            color = 'orange'
        elif forgery_score >= 20:
            assessment = 'QUESTIONABLE'
            color = 'yellow'
        else:
            assessment = 'LIKELY AUTHENTIC'
            color = 'green'

        self.results['authenticity'] = {
            'score': min(forgery_score, 100),
            'assessment': assessment,
            'color': color,
            'indicators': indicators
        }

    def _extract_email(self, header: str) -> str:
        """Extract email address from header"""
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header)
        return match.group(0) if match else None


def analyze_email_headers(headers_text: str) -> Dict:
    """
    Convenience function to analyze email headers

    Args:
        headers_text (str): Raw email headers

    Returns:
        Dict: Analysis results
    """
    analyzer = EmailHeaderAnalyzer()
    return analyzer.analyze(headers_text)
