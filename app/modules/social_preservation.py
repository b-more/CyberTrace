"""
Social Media Preservation Module
CyberTrace - Zambia Police Service

Social media content preservation and evidence collection toolkit.
Captures web pages, extracts metadata, submits to Wayback Machine,
flags content, and calculates integrity hashes.
"""

import re
import time
import hashlib
import logging
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse

import requests

logger = logging.getLogger('osint')


class SocialPreservation:
    """Social Media Content Preservation and Evidence Tool"""

    def __init__(self):
        self.results = {
            'url': None,
            'platform': None,
            'capture': {},
            'author_info': {},
            'engagement': {},
            'content_flags': [],
            'wayback_submission': {},
            'content_hash': None,
            'metadata': {
                'captured_at': None,
                'capture_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def capture_url(self, url: str) -> Dict:
        """
        Capture and preserve content from a URL.

        Args:
            url: URL to capture

        Returns:
            Dict with captured content and metadata
        """
        self.start_time = time.time()
        self.results['url'] = url
        self.results['metadata']['captured_at'] = datetime.utcnow().isoformat()

        capture = {
            'url': url,
            'status_code': None,
            'html': None,
            'text_content': None,
            'title': None,
            'description': None,
            'author': None,
            'published_date': None,
            'images': [],
            'links': [],
            'page_hash': None,
            'error': None
        }

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            self.api_calls += 1

            capture['status_code'] = response.status_code
            capture['html'] = response.text

            # Hash the raw HTML for integrity
            capture['page_hash'] = self.calculate_hash(response.text)
            self.results['content_hash'] = capture['page_hash']

            # Parse with BeautifulSoup
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract title
                title_tag = soup.find('title')
                capture['title'] = title_tag.get_text(strip=True) if title_tag else None

                # Extract text content
                # Remove script and style elements
                for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
                    tag.decompose()
                capture['text_content'] = soup.get_text(separator='\n', strip=True)

                # Extract meta description
                meta_desc = soup.find('meta', attrs={'name': 'description'})
                if meta_desc:
                    capture['description'] = meta_desc.get('content', '')

                # Extract og:description as fallback
                og_desc = soup.find('meta', attrs={'property': 'og:description'})
                if og_desc and not capture['description']:
                    capture['description'] = og_desc.get('content', '')

                # Published date from meta tags
                date_meta = (
                    soup.find('meta', attrs={'property': 'article:published_time'}) or
                    soup.find('meta', attrs={'name': 'date'}) or
                    soup.find('meta', attrs={'name': 'publish_date'}) or
                    soup.find('time')
                )
                if date_meta:
                    if date_meta.name == 'time':
                        capture['published_date'] = date_meta.get('datetime', date_meta.get_text())
                    else:
                        capture['published_date'] = date_meta.get('content', '')

                # Extract images
                for img in soup.find_all('img', src=True)[:20]:
                    src = img.get('src', '')
                    alt = img.get('alt', '')
                    if src:
                        capture['images'].append({
                            'src': src,
                            'alt': alt
                        })

                # Extract links
                for a in soup.find_all('a', href=True)[:50]:
                    href = a.get('href', '')
                    text = a.get_text(strip=True)
                    if href and not href.startswith('#'):
                        capture['links'].append({
                            'href': href,
                            'text': text[:100]
                        })

                # Detect platform and extract platform-specific data
                platform = self.detect_platform(url)
                self.results['platform'] = platform

                # Platform-specific author extraction
                try:
                    self.results['author_info'] = self.extract_author_info(soup, platform)
                except Exception as e:
                    logger.error(f"Author extraction failed: {e}")

                # Platform-specific engagement extraction
                try:
                    self.results['engagement'] = self.extract_engagement(soup, platform)
                except Exception as e:
                    logger.error(f"Engagement extraction failed: {e}")

            except ImportError:
                logger.error("BeautifulSoup is required for HTML parsing")
                capture['text_content'] = response.text
            except Exception as e:
                logger.error(f"HTML parsing failed: {e}")

        except requests.exceptions.RequestException as e:
            capture['error'] = f'Request failed: {str(e)}'
            logger.error(f"URL capture failed for {url}: {e}")
        except Exception as e:
            capture['error'] = f'Capture failed: {str(e)}'
            logger.error(f"URL capture error for {url}: {e}")

        self.results['capture'] = capture

        # Submit to Wayback Machine
        try:
            self.results['wayback_submission'] = self.submit_to_wayback(url)
        except Exception as e:
            logger.error(f"Wayback submission failed: {e}")
            self.results['wayback_submission'] = {'error': str(e)}

        # Flag content
        try:
            if capture.get('text_content'):
                self.results['content_flags'] = self.flag_content(
                    capture['text_content']
                )
        except Exception as e:
            logger.error(f"Content flagging failed: {e}")

        # Finalize metadata
        self.results['metadata']['capture_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def detect_platform(self, url: str) -> Optional[str]:
        """
        Detect the social media platform from a URL.

        Args:
            url: URL to analyze

        Returns:
            Platform name string or None
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        platform_map = {
            'facebook.com': 'facebook',
            'www.facebook.com': 'facebook',
            'fb.com': 'facebook',
            'm.facebook.com': 'facebook',
            'twitter.com': 'twitter',
            'www.twitter.com': 'twitter',
            'x.com': 'twitter',
            'www.x.com': 'twitter',
            'instagram.com': 'instagram',
            'www.instagram.com': 'instagram',
            'tiktok.com': 'tiktok',
            'www.tiktok.com': 'tiktok',
            'vm.tiktok.com': 'tiktok',
            'youtube.com': 'youtube',
            'www.youtube.com': 'youtube',
            'youtu.be': 'youtube',
            'm.youtube.com': 'youtube',
            'linkedin.com': 'linkedin',
            'www.linkedin.com': 'linkedin',
            'reddit.com': 'reddit',
            'www.reddit.com': 'reddit',
            'old.reddit.com': 'reddit',
        }

        for domain_key, platform in platform_map.items():
            if domain == domain_key or domain.endswith('.' + domain_key):
                return platform

        return None

    def submit_to_wayback(self, url: str) -> Dict:
        """
        Submit a URL to the Internet Archive Wayback Machine for preservation.

        Args:
            url: URL to submit

        Returns:
            Dict with submission result
        """
        submission = {
            'submitted': False,
            'archive_url': None,
            'error': None
        }

        try:
            save_url = f"https://web.archive.org/save/{url}"
            headers = {
                'User-Agent': 'CyberTrace-ZambiaPolice Evidence Preservation'
            }
            response = requests.post(save_url, headers=headers, timeout=30)
            self.api_calls += 1

            if response.status_code in (200, 302):
                submission['submitted'] = True
                # Try to extract archive URL from headers
                archive_url = response.headers.get('Content-Location')
                if archive_url:
                    submission['archive_url'] = f"https://web.archive.org{archive_url}"
                else:
                    submission['archive_url'] = save_url
            else:
                submission['error'] = f'Wayback Machine returned status {response.status_code}'

        except requests.exceptions.RequestException as e:
            submission['error'] = f'Submission failed: {str(e)}'
            logger.warning(f"Wayback Machine submission failed for {url}: {e}")
        except Exception as e:
            submission['error'] = f'Submission error: {str(e)}'

        return submission

    def extract_author_info(self, soup, platform: Optional[str]) -> Dict:
        """
        Extract author information from the page based on platform.

        Args:
            soup: BeautifulSoup parsed page
            platform: Detected platform name

        Returns:
            Dict with author information
        """
        author = {
            'name': None,
            'username': None,
            'profile_url': None,
            'verified': False,
            'bio': None,
            'followers': None,
            'error': None
        }

        try:
            if platform == 'twitter':
                # Open Graph author
                og_title = soup.find('meta', attrs={'property': 'og:title'})
                if og_title:
                    author['name'] = og_title.get('content', '')

                # Look for @username in page
                user_link = soup.find('a', href=re.compile(r'/[a-zA-Z0-9_]+$'))
                if user_link:
                    href = user_link.get('href', '')
                    author['username'] = href.strip('/')

            elif platform == 'facebook':
                og_title = soup.find('meta', attrs={'property': 'og:title'})
                if og_title:
                    author['name'] = og_title.get('content', '')

                og_url = soup.find('meta', attrs={'property': 'og:url'})
                if og_url:
                    author['profile_url'] = og_url.get('content', '')

            elif platform == 'instagram':
                og_title = soup.find('meta', attrs={'property': 'og:title'})
                if og_title:
                    content = og_title.get('content', '')
                    # Instagram format: "Name (@username) ..."
                    match = re.match(r'(.+?)\s*\(@(\w+)\)', content)
                    if match:
                        author['name'] = match.group(1).strip()
                        author['username'] = match.group(2)
                    else:
                        author['name'] = content

            elif platform == 'youtube':
                # Channel name from og:title or link[name="title"]
                og_title = soup.find('meta', attrs={'property': 'og:title'})
                if og_title:
                    author['name'] = og_title.get('content', '')

                link_author = soup.find('link', attrs={'itemprop': 'name'})
                if link_author:
                    author['username'] = link_author.get('content', '')

            elif platform == 'tiktok':
                og_title = soup.find('meta', attrs={'property': 'og:title'})
                if og_title:
                    author['name'] = og_title.get('content', '')

            else:
                # Generic extraction
                # Try meta author tag
                meta_author = soup.find('meta', attrs={'name': 'author'})
                if meta_author:
                    author['name'] = meta_author.get('content', '')

                # Try og:site_name
                og_site = soup.find('meta', attrs={'property': 'og:site_name'})
                if og_site and not author['name']:
                    author['name'] = og_site.get('content', '')

        except Exception as e:
            author['error'] = f'Author extraction failed: {str(e)}'
            logger.error(f"Author extraction error: {e}")

        return author

    def extract_engagement(self, soup, platform: Optional[str]) -> Dict:
        """
        Extract engagement metrics from the page based on platform.

        Args:
            soup: BeautifulSoup parsed page
            platform: Detected platform name

        Returns:
            Dict with engagement metrics
        """
        engagement = {
            'likes': None,
            'shares': None,
            'comments': None,
            'views': None,
            'retweets': None,
            'reactions': None,
            'error': None
        }

        try:
            text = soup.get_text()

            # Generic number extraction patterns
            like_patterns = [
                r'(\d[\d,.KkMm]*)\s*(?:likes?|Likes?)',
                r'(?:likes?|Likes?)\s*(\d[\d,.KkMm]*)',
            ]
            share_patterns = [
                r'(\d[\d,.KkMm]*)\s*(?:shares?|Shares?|Retweets?|retweets?)',
                r'(?:shares?|Shares?)\s*(\d[\d,.KkMm]*)',
            ]
            comment_patterns = [
                r'(\d[\d,.KkMm]*)\s*(?:comments?|Comments?|replies|Replies)',
                r'(?:comments?|Comments?)\s*(\d[\d,.KkMm]*)',
            ]
            view_patterns = [
                r'(\d[\d,.KkMm]*)\s*(?:views?|Views?)',
                r'(?:views?|Views?)\s*(\d[\d,.KkMm]*)',
            ]

            def find_metric(patterns):
                for pattern in patterns:
                    match = re.search(pattern, text)
                    if match:
                        return match.group(1)
                return None

            engagement['likes'] = find_metric(like_patterns)
            engagement['shares'] = find_metric(share_patterns)
            engagement['comments'] = find_metric(comment_patterns)
            engagement['views'] = find_metric(view_patterns)

            # Platform-specific OG meta
            if platform == 'twitter':
                # Twitter may have retweet count in meta
                pass

        except Exception as e:
            engagement['error'] = f'Engagement extraction failed: {str(e)}'
            logger.error(f"Engagement extraction error: {e}")

        return engagement

    def flag_content(self, text: str, categories: Optional[List[str]] = None) -> List[Dict]:
        """
        Flag content by matching keywords for various categories.

        Args:
            text: Text content to analyze
            categories: Optional list of categories to check.
                        Defaults to all categories.

        Returns:
            List of flag dicts with category, keywords found, and severity
        """
        flags = []

        keyword_categories = {
            'hate_speech': {
                'keywords': [
                    'hate', 'racial slur', 'supremacy', 'inferior race',
                    'ethnic cleansing', 'kill all', 'exterminate'
                ],
                'severity': 'high'
            },
            'threats': {
                'keywords': [
                    'kill you', 'bomb', 'shoot', 'murder', 'death threat',
                    'i will find you', 'burn your', 'attack', 'assassinate'
                ],
                'severity': 'critical'
            },
            'fraud': {
                'keywords': [
                    'send money', 'wire transfer', 'western union', 'moneygram',
                    'bitcoin payment', 'investment opportunity', 'guaranteed returns',
                    'double your money', 'lottery winner', 'inheritance',
                    'nigerian prince', 'advance fee', 'phishing'
                ],
                'severity': 'high'
            },
            'cybercrime': {
                'keywords': [
                    'hack', 'crack', 'ddos', 'ransomware', 'malware',
                    'exploit', 'zero day', 'data breach', 'stolen data',
                    'credit card dump', 'carding', 'fullz'
                ],
                'severity': 'high'
            },
            'drugs': {
                'keywords': [
                    'cocaine', 'heroin', 'methamphetamine', 'fentanyl',
                    'drug deal', 'narcotics', 'controlled substance'
                ],
                'severity': 'high'
            },
            'sexual_exploitation': {
                'keywords': [
                    'child exploitation', 'underage', 'csam', 'trafficking',
                    'sexual abuse', 'exploitation material'
                ],
                'severity': 'critical'
            },
            'terrorism': {
                'keywords': [
                    'terrorist', 'jihad', 'extremist', 'radicalize',
                    'bomb making', 'ied', 'martyr operation'
                ],
                'severity': 'critical'
            }
        }

        # Filter to requested categories
        if categories:
            keyword_categories = {
                k: v for k, v in keyword_categories.items()
                if k in categories
            }

        text_lower = text.lower()

        for category, config in keyword_categories.items():
            found_keywords = []
            for keyword in config['keywords']:
                if keyword.lower() in text_lower:
                    found_keywords.append(keyword)

            if found_keywords:
                flags.append({
                    'category': category,
                    'severity': config['severity'],
                    'keywords_found': found_keywords,
                    'match_count': len(found_keywords)
                })

        return flags

    def calculate_hash(self, content: str) -> str:
        """
        Calculate SHA-256 hash for content integrity verification.

        Args:
            content: Content string to hash

        Returns:
            SHA-256 hex digest string
        """
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()


def preserve_url(url: str) -> Dict:
    """
    Convenience function to capture and preserve a URL.

    Args:
        url: URL to preserve

    Returns:
        Dict with preservation results
    """
    preserver = SocialPreservation()
    return preserver.capture_url(url)
