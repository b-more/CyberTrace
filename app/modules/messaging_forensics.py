"""
Messaging Forensics Module
CyberTrace - Zambia Police Service

Chat export analysis toolkit for WhatsApp and other messaging platforms.
Includes message parsing, indicator extraction, link analysis,
keyword search, and statistical analysis.
"""

import re
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime
from collections import defaultdict, Counter

logger = logging.getLogger('osint')


class MessagingForensics:
    """Messaging Platform Forensics and Analysis Tool"""

    def __init__(self):
        self.results = {
            'messages': [],
            'message_count': 0,
            'indicators': {},
            'links': [],
            'keyword_matches': [],
            'statistics': {},
            'platform': None,
            'metadata': {
                'analyzed_at': None,
                'analysis_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def parse_whatsapp_export(self, file_path: str) -> List[Dict]:
        """
        Parse a WhatsApp chat export file.

        Supports common WhatsApp export formats:
        [DD/MM/YYYY, HH:MM:SS] - Sender: Message
        DD/MM/YYYY, HH:MM - Sender: Message

        Args:
            file_path: Path to the WhatsApp export text file

        Returns:
            List of parsed message dicts
        """
        messages = []

        # Regex pattern for WhatsApp message lines
        pattern = re.compile(
            r'\[?(\d{1,2}/\d{1,2}/\d{2,4}),?\s*'
            r'(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)\]?\s*-?\s*'
            r'([^:]+):\s*(.+)',
            re.DOTALL
        )

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')
            current_message = None

            for line in lines:
                match = pattern.match(line)
                if match:
                    # Save previous message if exists
                    if current_message:
                        messages.append(current_message)

                    date_str = match.group(1).strip()
                    time_str = match.group(2).strip()
                    sender = match.group(3).strip()
                    text = match.group(4).strip()

                    # Parse date/time
                    timestamp = self._parse_whatsapp_datetime(date_str, time_str)

                    # Detect media messages
                    is_media = False
                    media_type = None
                    media_indicators = [
                        '<media omitted>', 'image omitted', 'video omitted',
                        'audio omitted', 'document omitted', 'sticker omitted',
                        'gif omitted', 'contact card omitted'
                    ]
                    text_lower = text.lower()
                    for indicator in media_indicators:
                        if indicator in text_lower:
                            is_media = True
                            media_type = indicator.replace(' omitted', '').replace('<', '').replace('>', '')
                            break

                    current_message = {
                        'date': date_str,
                        'time': time_str,
                        'timestamp': timestamp,
                        'sender': sender,
                        'text': text,
                        'is_media': is_media,
                        'media_type': media_type,
                        'is_system': False
                    }
                else:
                    # Continuation of previous message or system message
                    if current_message and line.strip():
                        current_message['text'] += '\n' + line.strip()
                    elif line.strip():
                        # System message (no sender pattern)
                        messages.append({
                            'date': None,
                            'time': None,
                            'timestamp': None,
                            'sender': 'SYSTEM',
                            'text': line.strip(),
                            'is_media': False,
                            'media_type': None,
                            'is_system': True
                        })

            # Append last message
            if current_message:
                messages.append(current_message)

            self.results['messages'] = messages
            self.results['message_count'] = len(messages)
            self.results['platform'] = 'whatsapp'

            logger.info(f"Parsed {len(messages)} messages from WhatsApp export")

        except FileNotFoundError:
            logger.error(f"WhatsApp export file not found: {file_path}")
        except UnicodeDecodeError:
            logger.error(f"Encoding error reading file: {file_path}")
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
                # Retry with latin-1 encoding
                logger.info("Retrying with latin-1 encoding")
                return self.parse_whatsapp_export(file_path)
            except Exception as e:
                logger.error(f"Retry failed: {e}")
        except Exception as e:
            logger.error(f"WhatsApp export parse failed: {e}")

        return messages

    def _parse_whatsapp_datetime(self, date_str: str, time_str: str) -> Optional[str]:
        """Parse WhatsApp date and time strings into ISO format."""
        formats = [
            ('%d/%m/%Y %H:%M:%S', f'{date_str} {time_str}'),
            ('%d/%m/%y %H:%M:%S', f'{date_str} {time_str}'),
            ('%d/%m/%Y %H:%M', f'{date_str} {time_str}'),
            ('%d/%m/%y %H:%M', f'{date_str} {time_str}'),
            ('%m/%d/%Y %I:%M %p', f'{date_str} {time_str}'),
            ('%m/%d/%y %I:%M %p', f'{date_str} {time_str}'),
            ('%d/%m/%Y %I:%M:%S %p', f'{date_str} {time_str}'),
            ('%d/%m/%y %I:%M:%S %p', f'{date_str} {time_str}'),
        ]

        for fmt, dt_str in formats:
            try:
                dt = datetime.strptime(dt_str.strip(), fmt)
                return dt.isoformat()
            except (ValueError, TypeError):
                continue

        return f'{date_str} {time_str}'

    def extract_indicators(self, messages: List[Dict]) -> Dict:
        """
        Extract investigative indicators from messages (URLs, phone numbers, emails).

        Args:
            messages: List of message dicts

        Returns:
            Dict with extracted indicators by type
        """
        indicators = {
            'urls': [],
            'phone_numbers': [],
            'email_addresses': [],
            'crypto_addresses': [],
            'ip_addresses': []
        }

        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'
        )
        email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        )
        ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        # Basic crypto patterns
        btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        eth_pattern = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

        seen_urls = set()
        seen_emails = set()
        seen_phones = set()
        seen_ips = set()
        seen_crypto = set()

        for msg in messages:
            text = msg.get('text', '')
            sender = msg.get('sender', 'Unknown')
            timestamp = msg.get('timestamp')

            # URLs
            for match in url_pattern.finditer(text):
                url = match.group()
                if url not in seen_urls:
                    seen_urls.add(url)
                    indicators['urls'].append({
                        'value': url,
                        'sender': sender,
                        'timestamp': timestamp,
                        'context': text[:200]
                    })

            # Email addresses
            for match in email_pattern.finditer(text):
                email = match.group().lower()
                if email not in seen_emails:
                    seen_emails.add(email)
                    indicators['email_addresses'].append({
                        'value': email,
                        'sender': sender,
                        'timestamp': timestamp
                    })

            # Phone numbers
            try:
                import phonenumbers
                for match in phonenumbers.PhoneNumberMatcher(text, 'ZM'):
                    number = phonenumbers.format_number(
                        match.number,
                        phonenumbers.PhoneNumberFormat.E164
                    )
                    if number not in seen_phones:
                        seen_phones.add(number)
                        indicators['phone_numbers'].append({
                            'value': number,
                            'sender': sender,
                            'timestamp': timestamp
                        })
            except ImportError:
                # Fallback regex for phone numbers
                phone_regex = re.compile(
                    r'(?:\+?260|0)\s*\d{2}\s*\d{3}\s*\d{4}|\+?\d{10,15}'
                )
                for match in phone_regex.finditer(text):
                    number = re.sub(r'\s', '', match.group())
                    if number not in seen_phones:
                        seen_phones.add(number)
                        indicators['phone_numbers'].append({
                            'value': number,
                            'sender': sender,
                            'timestamp': timestamp
                        })
            except Exception as e:
                logger.debug(f"Phone number extraction error: {e}")

            # IP addresses
            for match in ip_pattern.finditer(text):
                ip = match.group()
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    indicators['ip_addresses'].append({
                        'value': ip,
                        'sender': sender,
                        'timestamp': timestamp
                    })

            # Crypto addresses
            for match in btc_pattern.finditer(text):
                addr = match.group()
                if addr not in seen_crypto:
                    seen_crypto.add(addr)
                    indicators['crypto_addresses'].append({
                        'value': addr,
                        'type': 'btc',
                        'sender': sender,
                        'timestamp': timestamp
                    })

            for match in eth_pattern.finditer(text):
                addr = match.group()
                if addr not in seen_crypto:
                    seen_crypto.add(addr)
                    indicators['crypto_addresses'].append({
                        'value': addr,
                        'type': 'eth',
                        'sender': sender,
                        'timestamp': timestamp
                    })

        self.results['indicators'] = indicators
        return indicators

    def extract_links(self, messages: List[Dict]) -> List[Dict]:
        """
        Extract and analyze links from messages.

        Args:
            messages: List of message dicts

        Returns:
            List of link analysis dicts
        """
        url_pattern = re.compile(
            r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)'
        )

        link_data = defaultdict(lambda: {
            'url': '',
            'domain': '',
            'senders': set(),
            'timestamps': [],
            'count': 0
        })

        for msg in messages:
            text = msg.get('text', '')
            sender = msg.get('sender', 'Unknown')
            timestamp = msg.get('timestamp')

            for match in url_pattern.finditer(text):
                url = match.group()
                # Extract domain
                domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/\s:]+)', url)
                domain = domain_match.group(1) if domain_match else url

                link_data[url]['url'] = url
                link_data[url]['domain'] = domain
                link_data[url]['senders'].add(sender)
                link_data[url]['timestamps'].append(timestamp)
                link_data[url]['count'] += 1

        # Convert to serializable format
        links = []
        for url, data in link_data.items():
            links.append({
                'url': data['url'],
                'domain': data['domain'],
                'senders': list(data['senders']),
                'timestamps': data['timestamps'],
                'count': data['count']
            })

        # Sort by count descending
        links.sort(key=lambda x: x['count'], reverse=True)

        self.results['links'] = links
        return links

    def keyword_search(self, messages: List[Dict], keywords: List[str]) -> List[Dict]:
        """
        Search messages for keywords and return matches with context.

        Args:
            messages: List of message dicts
            keywords: List of keywords to search for

        Returns:
            List of match dicts with context
        """
        matches = []
        keyword_patterns = [
            re.compile(re.escape(kw), re.IGNORECASE) for kw in keywords
        ]

        for msg in messages:
            text = msg.get('text', '')
            if not text:
                continue

            for i, pattern in enumerate(keyword_patterns):
                if pattern.search(text):
                    # Get surrounding context
                    match_obj = pattern.search(text)
                    start = max(0, match_obj.start() - 50)
                    end = min(len(text), match_obj.end() + 50)
                    context = text[start:end]

                    matches.append({
                        'keyword': keywords[i],
                        'sender': msg.get('sender', 'Unknown'),
                        'timestamp': msg.get('timestamp'),
                        'text': text,
                        'context': f'...{context}...' if start > 0 or end < len(text) else context,
                        'date': msg.get('date'),
                        'time': msg.get('time')
                    })

        self.results['keyword_matches'] = matches
        return matches

    def generate_statistics(self, messages: List[Dict]) -> Dict:
        """
        Generate statistical analysis of the chat.

        Args:
            messages: List of message dicts

        Returns:
            Dict with statistical analysis
        """
        stats = {
            'total_messages': len(messages),
            'participants': {},
            'date_distribution': {},
            'hourly_distribution': {},
            'media_count': 0,
            'media_types': {},
            'system_messages': 0,
            'avg_message_length': 0,
            'most_active_day': None,
            'most_active_hour': None,
            'first_message': None,
            'last_message': None,
            'duration_days': 0,
            'messages_per_day': 0
        }

        if not messages:
            return stats

        sender_counts = Counter()
        sender_lengths = defaultdict(list)
        date_counts = Counter()
        hour_counts = Counter()
        media_types = Counter()
        total_length = 0
        non_system_count = 0

        for msg in messages:
            if msg.get('is_system'):
                stats['system_messages'] += 1
                continue

            non_system_count += 1
            sender = msg.get('sender', 'Unknown')
            text = msg.get('text', '')

            sender_counts[sender] += 1
            sender_lengths[sender].append(len(text))
            total_length += len(text)

            # Date distribution
            date = msg.get('date')
            if date:
                date_counts[date] += 1

            # Hour distribution
            time_str = msg.get('time', '')
            if time_str:
                hour_match = re.match(r'(\d{1,2}):', time_str)
                if hour_match:
                    hour = int(hour_match.group(1))
                    # Handle AM/PM
                    if 'pm' in time_str.lower() and hour != 12:
                        hour += 12
                    elif 'am' in time_str.lower() and hour == 12:
                        hour = 0
                    hour_counts[str(hour).zfill(2)] += 1

            # Media stats
            if msg.get('is_media'):
                stats['media_count'] += 1
                media_type = msg.get('media_type', 'unknown')
                media_types[media_type] += 1

        # Participant stats
        for sender, count in sender_counts.most_common():
            lengths = sender_lengths[sender]
            stats['participants'][sender] = {
                'message_count': count,
                'percentage': round(count / max(non_system_count, 1) * 100, 1),
                'avg_message_length': round(sum(lengths) / max(len(lengths), 1), 1),
                'total_characters': sum(lengths)
            }

        stats['date_distribution'] = dict(date_counts.most_common())
        stats['hourly_distribution'] = dict(sorted(hour_counts.items()))
        stats['media_types'] = dict(media_types)

        if non_system_count > 0:
            stats['avg_message_length'] = round(total_length / non_system_count, 1)

        if date_counts:
            stats['most_active_day'] = date_counts.most_common(1)[0][0]

        if hour_counts:
            stats['most_active_hour'] = hour_counts.most_common(1)[0][0]

        # Date range
        timestamps = [
            msg.get('timestamp') for msg in messages
            if msg.get('timestamp') and not msg.get('is_system')
        ]
        if timestamps:
            timestamps.sort()
            stats['first_message'] = timestamps[0]
            stats['last_message'] = timestamps[-1]
            try:
                first = datetime.fromisoformat(timestamps[0])
                last = datetime.fromisoformat(timestamps[-1])
                stats['duration_days'] = (last - first).days
                if stats['duration_days'] > 0:
                    stats['messages_per_day'] = round(
                        non_system_count / stats['duration_days'], 1
                    )
            except (ValueError, TypeError):
                pass

        self.results['statistics'] = stats
        return stats

    def check_whatsapp_status(self, phone_number: str) -> Dict:
        """
        Check WhatsApp status for a phone number (placeholder).

        Args:
            phone_number: Phone number to check

        Returns:
            Dict with status information
        """
        return {
            'phone_number': phone_number,
            'has_whatsapp': None,
            'profile_photo': None,
            'about': None,
            'last_seen': None,
            'error': 'WhatsApp status check not yet implemented - placeholder'
        }


def analyze_chat_export(file_path: str) -> Dict:
    """
    Convenience function to analyze a WhatsApp chat export.

    Args:
        file_path: Path to the WhatsApp export text file

    Returns:
        Dict with complete analysis results
    """
    forensics = MessagingForensics()
    messages = forensics.parse_whatsapp_export(file_path)
    if messages:
        forensics.extract_indicators(messages)
        forensics.extract_links(messages)
        forensics.generate_statistics(messages)
    return forensics.results
