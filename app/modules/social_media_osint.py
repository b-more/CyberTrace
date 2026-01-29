"""
Social Media OSINT Module
CyberTrace OSINT Platform - Zambia Police Service

Comprehensive social media profile discovery and investigation
"""

import re
import json
from urllib.parse import quote, urlencode
from datetime import datetime


def validate_username(username):
    """
    Validate and clean username

    Args:
        username (str): Username to validate

    Returns:
        dict: Validation results with cleaned username
    """
    if not username or not username.strip():
        return {
            'valid': False,
            'error': 'Username cannot be empty'
        }

    # Clean username - remove @ symbol and whitespace
    cleaned = username.strip().lstrip('@')

    # Basic validation - alphanumeric, dots, underscores, hyphens
    if not re.match(r'^[a-zA-Z0-9._-]{1,30}$', cleaned):
        return {
            'valid': False,
            'error': 'Invalid username format. Use only letters, numbers, dots, underscores, and hyphens.'
        }

    return {
        'valid': True,
        'username': cleaned,
        'original': username
    }


def generate_facebook_searches(username):
    """
    Generate Facebook search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of Facebook search methods
    """
    searches = []

    # Direct profile search
    searches.append({
        'name': 'Facebook Profile Search',
        'description': 'Search for profile by username',
        'url': f'https://www.facebook.com/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Facebook search
    searches.append({
        'name': 'Facebook People Search',
        'description': 'Search Facebook for people with this username',
        'url': f'https://www.facebook.com/search/people/?q={quote(username)}',
        'method': 'search',
        'priority': 'high'
    })

    # Facebook public posts
    searches.append({
        'name': 'Facebook Posts Search',
        'description': 'Search public posts mentioning this username',
        'url': f'https://www.facebook.com/search/posts/?q={quote(username)}',
        'method': 'search',
        'priority': 'medium'
    })

    # Facebook groups
    searches.append({
        'name': 'Facebook Groups',
        'description': 'Search groups where username might be mentioned',
        'url': f'https://www.facebook.com/search/groups/?q={quote(username)}',
        'method': 'search',
        'priority': 'medium'
    })

    # Facebook pages
    searches.append({
        'name': 'Facebook Pages',
        'description': 'Search Facebook pages',
        'url': f'https://www.facebook.com/search/pages/?q={quote(username)}',
        'method': 'search',
        'priority': 'low'
    })

    # Google search for Facebook profile
    searches.append({
        'name': 'Google: Facebook Profile',
        'description': 'Use Google to find Facebook profile',
        'url': f'https://www.google.com/search?q=site:facebook.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_twitter_searches(username):
    """
    Generate Twitter/X search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of Twitter search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'Twitter/X Profile',
        'description': 'Direct link to Twitter/X profile',
        'url': f'https://twitter.com/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Alternative X.com domain
    searches.append({
        'name': 'X.com Profile',
        'description': 'Alternative X.com domain',
        'url': f'https://x.com/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Twitter search
    searches.append({
        'name': 'Twitter Search',
        'description': 'Search Twitter for this username',
        'url': f'https://twitter.com/search?q={quote(username)}&src=typed_query',
        'method': 'search',
        'priority': 'high'
    })

    # Twitter advanced search - from user
    searches.append({
        'name': 'Tweets from User',
        'description': 'All tweets from this username',
        'url': f'https://twitter.com/search?q=from:{username}&src=typed_query',
        'method': 'search',
        'priority': 'high'
    })

    # Twitter advanced search - mentions
    searches.append({
        'name': 'Mentions of User',
        'description': 'Tweets mentioning this username',
        'url': f'https://twitter.com/search?q=@{username}&src=typed_query',
        'method': 'search',
        'priority': 'medium'
    })

    # Google search
    searches.append({
        'name': 'Google: Twitter Profile',
        'description': 'Use Google to find Twitter profile',
        'url': f'https://www.google.com/search?q=site:twitter.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_instagram_searches(username):
    """
    Generate Instagram search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of Instagram search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'Instagram Profile',
        'description': 'Direct link to Instagram profile',
        'url': f'https://www.instagram.com/{username}/',
        'method': 'direct',
        'priority': 'high'
    })

    # Instagram tag search
    searches.append({
        'name': 'Instagram Tag Search',
        'description': 'Search posts tagged with username',
        'url': f'https://www.instagram.com/explore/tags/{username}/',
        'method': 'search',
        'priority': 'medium'
    })

    # Picuki (Instagram viewer)
    searches.append({
        'name': 'Picuki Viewer',
        'description': 'View Instagram profile via Picuki',
        'url': f'https://www.picuki.com/profile/{username}',
        'method': 'third_party',
        'priority': 'high'
    })

    # Imginn (Instagram viewer)
    searches.append({
        'name': 'Imginn Viewer',
        'description': 'View Instagram profile via Imginn',
        'url': f'https://imginn.com/{username}/',
        'method': 'third_party',
        'priority': 'high'
    })

    # Google search
    searches.append({
        'name': 'Google: Instagram Profile',
        'description': 'Use Google to find Instagram profile',
        'url': f'https://www.google.com/search?q=site:instagram.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_linkedin_searches(username):
    """
    Generate LinkedIn search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of LinkedIn search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'LinkedIn Profile',
        'description': 'Direct link to LinkedIn profile',
        'url': f'https://www.linkedin.com/in/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # LinkedIn people search
    searches.append({
        'name': 'LinkedIn People Search',
        'description': 'Search LinkedIn for people',
        'url': f'https://www.linkedin.com/search/results/people/?keywords={quote(username)}',
        'method': 'search',
        'priority': 'high'
    })

    # LinkedIn company search
    searches.append({
        'name': 'LinkedIn Company Search',
        'description': 'Search for companies with this name',
        'url': f'https://www.linkedin.com/search/results/companies/?keywords={quote(username)}',
        'method': 'search',
        'priority': 'low'
    })

    # Google search
    searches.append({
        'name': 'Google: LinkedIn Profile',
        'description': 'Use Google to find LinkedIn profile',
        'url': f'https://www.google.com/search?q=site:linkedin.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_tiktok_searches(username):
    """
    Generate TikTok search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of TikTok search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'TikTok Profile',
        'description': 'Direct link to TikTok profile',
        'url': f'https://www.tiktok.com/@{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # TikTok search
    searches.append({
        'name': 'TikTok Search',
        'description': 'Search TikTok for username',
        'url': f'https://www.tiktok.com/search/user?q={quote(username)}',
        'method': 'search',
        'priority': 'high'
    })

    # Google search
    searches.append({
        'name': 'Google: TikTok Profile',
        'description': 'Use Google to find TikTok profile',
        'url': f'https://www.google.com/search?q=site:tiktok.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_youtube_searches(username):
    """
    Generate YouTube search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of YouTube search methods
    """
    searches = []

    # Direct channel
    searches.append({
        'name': 'YouTube Channel (@username)',
        'description': 'Direct link to YouTube channel',
        'url': f'https://www.youtube.com/@{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Legacy channel URL
    searches.append({
        'name': 'YouTube Channel (legacy)',
        'description': 'Legacy channel URL format',
        'url': f'https://www.youtube.com/user/{username}',
        'method': 'direct',
        'priority': 'medium'
    })

    # YouTube search
    searches.append({
        'name': 'YouTube Search',
        'description': 'Search YouTube for channels',
        'url': f'https://www.youtube.com/results?search_query={quote(username)}',
        'method': 'search',
        'priority': 'high'
    })

    # Google search
    searches.append({
        'name': 'Google: YouTube Channel',
        'description': 'Use Google to find YouTube channel',
        'url': f'https://www.google.com/search?q=site:youtube.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_reddit_searches(username):
    """
    Generate Reddit search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of Reddit search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'Reddit Profile',
        'description': 'Direct link to Reddit profile',
        'url': f'https://www.reddit.com/user/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Reddit search
    searches.append({
        'name': 'Reddit Search',
        'description': 'Search Reddit for posts by user',
        'url': f'https://www.reddit.com/search/?q=author:{username}',
        'method': 'search',
        'priority': 'high'
    })

    # Google search
    searches.append({
        'name': 'Google: Reddit Profile',
        'description': 'Use Google to find Reddit activity',
        'url': f'https://www.google.com/search?q=site:reddit.com+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_github_searches(username):
    """
    Generate GitHub search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of GitHub search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'GitHub Profile',
        'description': 'Direct link to GitHub profile',
        'url': f'https://github.com/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # GitHub user search
    searches.append({
        'name': 'GitHub User Search',
        'description': 'Search GitHub for users',
        'url': f'https://github.com/search?q={quote(username)}&type=users',
        'method': 'search',
        'priority': 'high'
    })

    # GitHub repositories
    searches.append({
        'name': 'GitHub Repositories',
        'description': 'Search repositories by this user',
        'url': f'https://github.com/search?q=user:{username}&type=repositories',
        'method': 'search',
        'priority': 'medium'
    })

    return searches


def generate_telegram_searches(username):
    """
    Generate Telegram search URLs for username

    Args:
        username (str): Username to search

    Returns:
        list: List of Telegram search methods
    """
    searches = []

    # Direct profile
    searches.append({
        'name': 'Telegram Profile',
        'description': 'Direct link to Telegram profile',
        'url': f'https://t.me/{username}',
        'method': 'direct',
        'priority': 'high'
    })

    # Telegram channel search via Google
    searches.append({
        'name': 'Google: Telegram Channel',
        'description': 'Search for Telegram channel/profile',
        'url': f'https://www.google.com/search?q=site:t.me+{quote(username)}',
        'method': 'google',
        'priority': 'medium'
    })

    return searches


def generate_username_search_engines(username):
    """
    Generate searches using username search engines

    Args:
        username (str): Username to search

    Returns:
        list: List of search engine methods
    """
    searches = []

    # Namechk
    searches.append({
        'name': 'Namechk',
        'description': 'Check username across 100+ platforms',
        'url': f'https://namechk.com/{username}',
        'method': 'aggregator',
        'priority': 'high'
    })

    # WhatsMyName
    searches.append({
        'name': 'WhatsMyName',
        'description': 'Check username across 500+ websites',
        'url': f'https://whatsmyname.app/?q={username}',
        'method': 'aggregator',
        'priority': 'high'
    })

    # Sherlock Project (info)
    searches.append({
        'name': 'Sherlock Project',
        'description': 'Open-source username search tool',
        'url': 'https://github.com/sherlock-project/sherlock',
        'method': 'tool',
        'priority': 'medium',
        'note': 'Install locally for comprehensive search'
    })

    # Social-Searcher
    searches.append({
        'name': 'Social-Searcher',
        'description': 'Real-time social media search',
        'url': f'https://www.social-searcher.com/search-users/?q6={quote(username)}',
        'method': 'aggregator',
        'priority': 'medium'
    })

    return searches


def perform_social_media_investigation(username, platforms=None):
    """
    Perform comprehensive social media investigation

    Args:
        username (str): Username to investigate
        platforms (list): List of platforms to search (None = all)

    Returns:
        dict: Investigation results
    """
    # Validate username
    validation = validate_username(username)
    if not validation['valid']:
        return {
            'success': False,
            'error': validation['error']
        }

    cleaned_username = validation['username']

    # Generate all searches
    all_platforms = {
        'facebook': generate_facebook_searches(cleaned_username),
        'twitter': generate_twitter_searches(cleaned_username),
        'instagram': generate_instagram_searches(cleaned_username),
        'linkedin': generate_linkedin_searches(cleaned_username),
        'tiktok': generate_tiktok_searches(cleaned_username),
        'youtube': generate_youtube_searches(cleaned_username),
        'reddit': generate_reddit_searches(cleaned_username),
        'github': generate_github_searches(cleaned_username),
        'telegram': generate_telegram_searches(cleaned_username)
    }

    # Filter by selected platforms if specified
    if platforms:
        all_platforms = {k: v for k, v in all_platforms.items() if k in platforms}

    # Add username search engines
    search_engines = generate_username_search_engines(cleaned_username)

    # Calculate statistics
    total_searches = sum(len(searches) for searches in all_platforms.values()) + len(search_engines)
    platforms_count = len(all_platforms)

    return {
        'success': True,
        'username': cleaned_username,
        'original_input': validation['original'],
        'timestamp': datetime.utcnow().isoformat(),
        'platforms': all_platforms,
        'search_engines': search_engines,
        'statistics': {
            'total_searches': total_searches,
            'platforms_searched': platforms_count,
            'search_engines': len(search_engines)
        }
    }


def get_available_platforms():
    """
    Get list of available social media platforms

    Returns:
        list: List of platform information
    """
    return [
        {'id': 'facebook', 'name': 'Facebook', 'icon': 'facebook', 'color': '#1877F2'},
        {'id': 'twitter', 'name': 'Twitter/X', 'icon': 'twitter-x', 'color': '#000000'},
        {'id': 'instagram', 'name': 'Instagram', 'icon': 'instagram', 'color': '#E4405F'},
        {'id': 'linkedin', 'name': 'LinkedIn', 'icon': 'linkedin', 'color': '#0A66C2'},
        {'id': 'tiktok', 'name': 'TikTok', 'icon': 'tiktok', 'color': '#000000'},
        {'id': 'youtube', 'name': 'YouTube', 'icon': 'youtube', 'color': '#FF0000'},
        {'id': 'reddit', 'name': 'Reddit', 'icon': 'reddit', 'color': '#FF4500'},
        {'id': 'github', 'name': 'GitHub', 'icon': 'github', 'color': '#181717'},
        {'id': 'telegram', 'name': 'Telegram', 'icon': 'telegram', 'color': '#26A5E4'}
    ]
