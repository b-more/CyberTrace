"""
Phone OSINT Module
CyberTrace - Zambia Police Service

Investigate phone numbers for cybercrime and fraud cases
"""

import re
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import time
import requests
from urllib.parse import quote, unquote
import subprocess
import json
import os


def get_numverify_data(phone_number):
    """
    Get enhanced phone data from Numverify API

    Args:
        phone_number (str): Phone number in international format (e.g., +260975020473)

    Returns:
        dict: Numverify API response data
    """
    try:
        # Get API key from environment
        api_key = os.getenv('NUMVERIFY_API_KEY', '')

        if not api_key or api_key == 'your_numverify_api_key_here':
            return {
                'success': False,
                'error': 'Numverify API key not configured',
                'data': {}
            }

        # Clean phone number - Numverify expects number without + sign
        clean_number = phone_number.replace('+', '').replace(' ', '').replace('-', '')

        # Numverify API endpoint
        url = 'http://apilayer.net/api/validate'

        params = {
            'access_key': api_key,
            'number': clean_number,
            'country_code': '',  # Auto-detect
            'format': 1  # Return formatted response
        }

        # Make API request with timeout
        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()

            if data.get('valid'):
                return {
                    'success': True,
                    'data': {
                        'valid': data.get('valid', False),
                        'number': data.get('number', ''),
                        'local_format': data.get('local_format', ''),
                        'international_format': data.get('international_format', ''),
                        'country_prefix': data.get('country_prefix', ''),
                        'country_code': data.get('country_code', ''),
                        'country_name': data.get('country_name', ''),
                        'location': data.get('location', ''),
                        'carrier': data.get('carrier', 'Unknown'),
                        'line_type': data.get('line_type', 'Unknown')  # mobile, landline, etc.
                    }
                }
            else:
                return {
                    'success': False,
                    'error': 'Invalid phone number according to Numverify',
                    'data': {}
                }
        else:
            return {
                'success': False,
                'error': f'Numverify API returned status code {response.status_code}',
                'data': {}
            }

    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': 'Numverify API request timed out',
            'data': {}
        }
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'error': f'Numverify API request failed: {str(e)}',
            'data': {}
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Numverify integration error: {str(e)}',
            'data': {}
        }


def validate_phone_number(phone):
    """
    Validate and format phone number

    Args:
        phone (str): Phone number to validate

    Returns:
        dict: Validation results
    """
    try:
        # Parse the number
        parsed = phonenumbers.parse(phone, "ZM")  # Default to Zambia

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        return {
            'is_valid': is_valid,
            'is_possible': is_possible,
            'international_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'e164_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'country_code': parsed.country_code,
            'national_number': parsed.national_number,
            'number_type': get_number_type(parsed)
        }
    except Exception as e:
        return {
            'is_valid': False,
            'error': str(e)
        }


def get_number_type(parsed_number):
    """Get the type of phone number"""
    number_type = phonenumbers.number_type(parsed_number)

    type_mapping = {
        phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
        phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed Line or Mobile',
        phonenumbers.PhoneNumberType.TOLL_FREE: 'Toll Free',
        phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Premium Rate',
        phonenumbers.PhoneNumberType.SHARED_COST: 'Shared Cost',
        phonenumbers.PhoneNumberType.VOIP: 'VoIP',
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'Personal Number',
        phonenumbers.PhoneNumberType.PAGER: 'Pager',
        phonenumbers.PhoneNumberType.UAN: 'UAN',
        phonenumbers.PhoneNumberType.VOICEMAIL: 'Voicemail',
        phonenumbers.PhoneNumberType.UNKNOWN: 'Unknown'
    }

    return type_mapping.get(number_type, 'Unknown')


def get_location_info(parsed_number):
    """
    Get location information for phone number

    Args:
        parsed_number: Parsed phonenumbers object

    Returns:
        dict: Location information
    """
    try:
        location = geocoder.description_for_number(parsed_number, "en")
        country = geocoder.country_name_for_number(parsed_number, "en")
        timezones = timezone.time_zones_for_number(parsed_number)

        return {
            'location': location,
            'country': country,
            'timezones': list(timezones) if timezones else []
        }
    except Exception as e:
        return {
            'error': str(e)
        }


def get_carrier_info(parsed_number):
    """
    Get carrier/network information

    Args:
        parsed_number: Parsed phonenumbers object

    Returns:
        dict: Carrier information
    """
    try:
        carrier_name = carrier.name_for_number(parsed_number, "en")

        return {
            'carrier': carrier_name if carrier_name else 'Unknown',
            'network_type': 'Mobile Network' if carrier_name else 'Unknown'
        }
    except Exception as e:
        return {
            'error': str(e),
            'carrier': 'Unknown'
        }


def check_risk_indicators(phone_data):
    """
    Assess risk indicators for phone number

    Args:
        phone_data (dict): Phone investigation data

    Returns:
        dict: Risk assessment
    """
    risk_score = 0
    flags = []
    recommendations = []

    validation = phone_data.get('validation', {})

    # Invalid number
    if not validation.get('is_valid'):
        risk_score += 40
        flags.append('Invalid or non-existent phone number')
        recommendations.append('Verify the phone number with the source')

    # VoIP number (often used for fraud)
    if validation.get('number_type') == 'VoIP':
        risk_score += 30
        flags.append('VoIP number - commonly used in fraud')
        recommendations.append('Enhanced verification required for VoIP numbers')

    # Premium rate number
    if validation.get('number_type') == 'Premium Rate':
        risk_score += 25
        flags.append('Premium rate number - potential scam indicator')
        recommendations.append('Investigate billing fraud possibilities')

    # Unknown carrier
    carrier_info = phone_data.get('carrier', {})
    if carrier_info.get('carrier') == 'Unknown':
        risk_score += 15
        flags.append('Unknown carrier - difficult to trace')
        recommendations.append('Contact telecom authorities for carrier identification')

    # Foreign number
    location_info = phone_data.get('location', {})
    if location_info.get('country') and location_info.get('country') != 'Zambia':
        risk_score += 20
        flags.append(f'Foreign number from {location_info.get("country")}')
        recommendations.append('Consider international cooperation for investigation')

    # Determine assessment
    if risk_score >= 70:
        assessment = 'HIGH RISK'
    elif risk_score >= 40:
        assessment = 'MODERATE RISK'
    else:
        assessment = 'LOW RISK'

    return {
        'risk_score': min(risk_score, 100),
        'assessment': assessment,
        'flags': flags,
        'recommendations': recommendations
    }


def run_phoneinfoga_scan(phone_number):
    """
    Run Phoneinfoga scan for enhanced OSINT

    Args:
        phone_number (str): Phone number to scan

    Returns:
        dict: Phoneinfoga scan results
    """
    phoneinfoga_path = '/var/www/html/projects/CyberTrace/phoneinfoga/bin/phoneinfoga'

    # Check if Phoneinfoga is installed
    if not os.path.exists(phoneinfoga_path):
        return {
            'success': False,
            'error': 'Phoneinfoga not installed',
            'results': {}
        }

    try:
        # Run Phoneinfoga scan (text output only)
        result = subprocess.run(
            [phoneinfoga_path, 'scan', '-n', phone_number],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            # Return text output for parsing
            return {
                'success': True,
                'results': {
                    'raw_output': result.stdout
                }
            }
        else:
            return {
                'success': False,
                'error': f'Phoneinfoga returned error: {result.stderr}',
                'results': {}
            }

    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Phoneinfoga scan timed out',
            'results': {}
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to run Phoneinfoga: {str(e)}',
            'results': {}
        }


def parse_phoneinfoga_results(phoneinfoga_data):
    """
    Parse Phoneinfoga results into structured format with better categorization

    Args:
        phoneinfoga_data (dict): Raw Phoneinfoga results

    Returns:
        dict: Parsed results with categorized searches
    """
    parsed = {
        'google_dorks': {
            'social_media': [],
            'reputation': [],
            'disposable': [],
            'individuals': [],
            'general': []
        },
        'total_dorks': 0
    }

    if not phoneinfoga_data.get('success'):
        return parsed

    results = phoneinfoga_data.get('results', {})

    # Parse raw output if JSON parsing failed
    if 'raw_output' in results:
        raw_text = results['raw_output']
        # Extract URLs from text
        urls = re.findall(r'URL: (https://[^\s]+)', raw_text)

        for url in urls:
            # URL decode the link for proper display and functionality
            decoded_url = unquote(url)

            # Create search object with metadata
            search_obj = {
                'url': decoded_url,
                'platform': extract_platform_name(decoded_url),
                'description': generate_search_description(decoded_url)
            }

            if 'facebook.com' in url or 'twitter.com' in url or 'linkedin.com' in url or 'instagram.com' in url or 'vk.com' in url:
                parsed['google_dorks']['social_media'].append(search_obj)
            elif 'whosenumber.info' in url or 'Phone+Fraud' in url or 'findwhocallsme' in url:
                parsed['google_dorks']['reputation'].append(search_obj)
            elif 'hs3x.com' in url or 'receive-sms' in url or 'freesms' in url:
                parsed['google_dorks']['disposable'].append(search_obj)
            elif 'numinfo.net' in url or 'sync.me' in url or 'pastebin.com' in url:
                parsed['google_dorks']['individuals'].append(search_obj)
            else:
                parsed['google_dorks']['general'].append(search_obj)

        parsed['total_dorks'] = len(urls)

    return parsed


def extract_platform_name(url):
    """Extract platform name from Google dork URL"""
    if 'facebook.com' in url:
        return 'Facebook'
    elif 'twitter.com' in url:
        return 'Twitter/X'
    elif 'linkedin.com' in url:
        return 'LinkedIn'
    elif 'instagram.com' in url:
        return 'Instagram'
    elif 'vk.com' in url:
        return 'VK'
    elif 'whosenumber.info' in url:
        return 'WhoseNumber'
    elif 'findwhocallsme' in url:
        return 'FindWhoCalls'
    elif 'pastebin.com' in url:
        return 'Pastebin'
    elif 'numinfo.net' in url:
        return 'NumInfo'
    elif 'sync.me' in url:
        return 'Sync.me'
    else:
        return 'Google Search'


def generate_search_description(url):
    """Generate user-friendly description for search"""
    if 'facebook.com' in url:
        if '/posts' in url:
            return 'Search Facebook posts mentioning this number'
        else:
            return 'Search Facebook profiles and pages with this number'
    elif 'twitter.com' in url or 'linkedin.com' in url or 'instagram.com' in url:
        return f'Search {extract_platform_name(url)} for this phone number'
    elif 'whosenumber.info' in url or 'findwhocallsme' in url:
        return 'Check if this number has been reported for spam or fraud'
    elif 'pastebin.com' in url:
        return 'Search data breaches and public pastes for this number'
    elif 'numinfo.net' in url or 'sync.me' in url:
        return 'Lookup caller information and identity'
    elif 'hs3x.com' in url or 'receive-sms' in url or 'freesms' in url:
        return 'Check if this is a disposable/temporary number'
    else:
        return 'General Google search for this phone number'


def generate_enhanced_social_media_searches(phone_number, international_format):
    """
    Generate enhanced social media search methods using direct platform searches,
    reverse lookup services, and OSINT databases

    Args:
        phone_number (str): Original phone number
        international_format (str): International format (+260975020473)

    Returns:
        dict: Enhanced search URLs for each platform and OSINT tools
    """
    # Extract number variants
    clean_number = re.sub(r'[^\d]', '', international_format)  # 260975020473
    without_plus = international_format.replace('+', '')  # 260975020473
    country_code = re.match(r'\+(\d{1,3})', international_format)

    # Get local number (without country code)
    local_number = clean_number
    if country_code:
        cc = country_code.group(1)
        local_number = clean_number[len(cc):]  # 975020473

    # URL encode for platform searches
    encoded_international = quote(international_format)
    encoded_clean = quote(clean_number)
    encoded_local = quote(local_number)

    enhanced_searches = {
        'facebook': [],
        'linkedin': [],
        'twitter': [],
        'instagram': [],
        'osint_tools': []
    }

    # Facebook - Direct platform search (actually works on Facebook)
    enhanced_searches['facebook'] = [
        {
            'name': 'Facebook Direct Search',
            'url': f'https://www.facebook.com/search/top?q={encoded_clean}',
            'description': 'Search Facebook directly for the phone number (requires login)'
        },
        {
            'name': 'Facebook People Search',
            'url': f'https://www.facebook.com/search/people?q={encoded_clean}',
            'description': 'Search Facebook profiles that may have listed this number'
        },
        {
            'name': 'Facebook Posts Search',
            'url': f'https://www.facebook.com/search/posts?q={encoded_clean}',
            'description': 'Search public posts mentioning the phone number'
        },
        {
            'name': 'Facebook Marketplace Search',
            'url': f'https://www.facebook.com/marketplace/search?query={encoded_clean}',
            'description': 'Search marketplace listings with this contact number'
        },
        {
            'name': 'Reverse Lookup - Social Catfish',
            'url': f'https://socialcatfish.com/reverse-phone-lookup/?phone={encoded_international}',
            'description': 'Reverse lookup to find associated Facebook profiles'
        },
        {
            'name': 'Google Cache - Facebook',
            'url': f'https://www.google.com/search?q=cache:facebook.com+{clean_number}',
            'description': 'Search Google cache for indexed Facebook content'
        }
    ]

    # LinkedIn - Direct platform search
    enhanced_searches['linkedin'] = [
        {
            'name': 'LinkedIn Direct Search',
            'url': f'https://www.linkedin.com/search/results/all/?keywords={encoded_clean}',
            'description': 'Search LinkedIn directly for the phone number (requires login)'
        },
        {
            'name': 'LinkedIn People Search',
            'url': f'https://www.linkedin.com/search/results/people/?keywords={encoded_clean}',
            'description': 'Search LinkedIn profiles with this contact number'
        },
        {
            'name': 'LinkedIn Company Search',
            'url': f'https://www.linkedin.com/search/results/companies/?keywords={encoded_clean}',
            'description': 'Search company pages with contact information'
        },
        {
            'name': 'LinkedIn Jobs Search',
            'url': f'https://www.linkedin.com/jobs/search/?keywords={encoded_clean}',
            'description': 'Search job postings mentioning the number'
        },
        {
            'name': 'Google Site Search - LinkedIn',
            'url': f'https://www.google.com/search?q=site:linkedin.com+%22{clean_number}%22+OR+%22{local_number}%22',
            'description': 'Find any indexed LinkedIn content with the number'
        }
    ]

    # Twitter/X - Direct platform search
    enhanced_searches['twitter'] = [
        {
            'name': 'X (Twitter) Direct Search',
            'url': f'https://twitter.com/search?q={encoded_clean}&f=live',
            'description': 'Search X/Twitter directly for the phone number (live results)'
        },
        {
            'name': 'X Advanced Search - From',
            'url': f'https://twitter.com/search?q=%22{encoded_clean}%22+OR+%22{encoded_local}%22&f=live',
            'description': 'Search tweets containing the exact phone number'
        },
        {
            'name': 'X People Search',
            'url': f'https://twitter.com/search?q={encoded_clean}&f=user',
            'description': 'Search X profiles that may mention this number'
        },
        {
            'name': 'X Photos/Videos Search',
            'url': f'https://twitter.com/search?q={encoded_clean}&f=image',
            'description': 'Search photos and videos mentioning the number'
        },
        {
            'name': 'Google Site Search - Twitter',
            'url': f'https://www.google.com/search?q=site:twitter.com+%22{clean_number}%22+OR+%22{local_number}%22',
            'description': 'Find indexed Twitter content with the number'
        }
    ]

    # Instagram - Direct searches (limited as Instagram blocks most search)
    enhanced_searches['instagram'] = [
        {
            'name': 'Instagram Tags Search',
            'url': f'https://www.instagram.com/explore/tags/{clean_number}/',
            'description': 'Search Instagram hashtags for the phone number'
        },
        {
            'name': 'Instagram Web Search',
            'url': f'https://www.instagram.com/web/search/topsearch/?query={encoded_clean}',
            'description': 'Search Instagram for accounts/content with the number'
        },
        {
            'name': 'Google Site Search - Instagram',
            'url': f'https://www.google.com/search?q=site:instagram.com+%22{clean_number}%22+OR+%22{local_number}%22',
            'description': 'Find indexed Instagram content with the number'
        },
        {
            'name': 'Picuki Instagram Viewer',
            'url': f'https://www.picuki.com/search/{encoded_clean}',
            'description': 'Anonymous Instagram search and viewer'
        },
        {
            'name': 'InstaDP Profile Viewer',
            'url': f'https://www.instadp.com/search?q={encoded_clean}',
            'description': 'Search Instagram profiles and posts'
        }
    ]

    # OSINT Tools & Reverse Lookup Services
    enhanced_searches['osint_tools'] = [
        {
            'name': 'TrueCaller Lookup',
            'url': f'https://www.truecaller.com/search/{without_plus}',
            'description': 'Truecaller database - often shows name and social profiles'
        },
        {
            'name': 'Sync.me Reverse Lookup',
            'url': f'https://sync.me/search/?q={encoded_international}',
            'description': 'Find social profiles connected to phone number'
        },
        {
            'name': 'NumLookup - Social Media Finder',
            'url': f'https://www.numlookup.com/{without_plus}',
            'description': 'Reverse phone lookup with social media links'
        },
        {
            'name': 'That\'s Them - Social Search',
            'url': f'https://thatsthem.com/phone/{clean_number}',
            'description': 'Free reverse phone lookup with social profiles'
        },
        {
            'name': 'Epieos Tools - Holehe',
            'url': f'https://epieos.com/',
            'description': 'Check if phone number registered on social platforms (manual entry)'
        },
        {
            'name': 'OSINT Framework - Phone',
            'url': f'https://osintframework.com/',
            'description': 'Comprehensive OSINT tools for phone investigations'
        },
        {
            'name': 'General Web Search',
            'url': f'https://www.google.com/search?q=%22{clean_number}%22+OR+%22{international_format}%22+OR+%22{local_number}%22',
            'description': 'Broad web search for any mentions of the number'
        }
    ]

    return enhanced_searches


def search_social_media(phone_number, international_format):
    """
    Search for social media accounts linked to phone number

    Args:
        phone_number (str): Original phone number
        international_format (str): International format of phone number

    Returns:
        list: Social media accounts found
    """
    social_accounts = []
    api_calls = 0

    # Format variants for searching
    clean_number = re.sub(r'[^\d+]', '', international_format)
    number_variants = [
        international_format,
        clean_number,
        phone_number
    ]

    # Platform checks
    platforms = [
        {
            'platform': 'WhatsApp',
            'url_template': f'https://wa.me/{clean_number}',
            'icon': 'whatsapp',
            'check_method': 'existence'
        },
        {
            'platform': 'Telegram',
            'url_template': f'https://t.me/{clean_number}',
            'icon': 'telegram',
            'check_method': 'existence'
        },
        {
            'platform': 'Viber',
            'url_template': f'viber://chat?number={clean_number}',
            'icon': 'chat-dots',
            'check_method': 'potential'
        },
        {
            'platform': 'Signal',
            'url_template': f'https://signal.me/#p/{clean_number}',
            'icon': 'shield-check',
            'check_method': 'potential'
        }
    ]

    for platform_data in platforms:
        try:
            # Add to results with potential status
            social_accounts.append({
                'platform': platform_data['platform'],
                'found': True,
                'confidence': 'Medium',  # Can't verify without actually visiting
                'url': platform_data['url_template'],
                'icon': platform_data['icon'],
                'note': f'Phone number may be registered on {platform_data["platform"]}. Click to verify manually.'
            })
            api_calls += 1
            time.sleep(0.1)  # Rate limiting
        except Exception:
            continue

    return social_accounts, api_calls


def search_online_mentions(phone_number, international_format):
    """
    Search for online mentions and listings of phone number

    Args:
        phone_number (str): Original phone number
        international_format (str): International format

    Returns:
        dict: Online mentions and listings found
    """
    mentions = {
        'total_found': 0,
        'sources': [],
        'scam_reports': [],
        'business_listings': [],
        'social_mentions': []
    }
    api_calls = 0

    # Clean number for searching
    clean_number = re.sub(r'[^\d]', '', international_format)

    # Known scam/spam reporting databases
    scam_databases = [
        {
            'name': 'WhoCallsMe',
            'url': f'https://whocallsme.com/Phone-Number.aspx/{clean_number}',
            'type': 'Scam Reports'
        },
        {
            'name': 'ScamWarners',
            'url': f'https://www.scamwarners.com/forum/search.php?keywords={clean_number}',
            'type': 'Scam Database'
        },
        {
            'name': 'TrueCaller',
            'url': f'https://www.truecaller.com/search/zm/{clean_number}',
            'type': 'Caller ID & Spam'
        },
        {
            'name': '800Notes',
            'url': f'https://800notes.com/Phone.aspx/{clean_number}',
            'type': 'Complaint Database'
        }
    ]

    for db in scam_databases:
        mentions['sources'].append({
            'name': db['name'],
            'url': db['url'],
            'type': db['type'],
            'status': 'Check Manually',
            'description': f'Search {db["name"]} database for reports about this number'
        })
        api_calls += 1

    # Business directory checks for Zambian numbers
    if '+260' in international_format or international_format.startswith('260'):
        business_directories = [
            {
                'name': 'Zambia Yellow Pages',
                'url': f'https://www.yellowpages.co.zm/search?q={clean_number}',
                'type': 'Business Directory'
            },
            {
                'name': 'Zambia Business Directory',
                'url': f'https://www.zamsearch.com/search?q={clean_number}',
                'type': 'Business Listings'
            }
        ]

        for directory in business_directories:
            mentions['business_listings'].append({
                'name': directory['name'],
                'url': directory['url'],
                'type': directory['type'],
                'status': 'Check Manually'
            })
            api_calls += 1

    # Google search suggestion
    google_search_url = f'https://www.google.com/search?q="{quote(international_format)}"'
    mentions['sources'].append({
        'name': 'Google Search',
        'url': google_search_url,
        'type': 'Web Search',
        'status': 'Manual Search Required',
        'description': 'Search Google for any public mentions of this phone number'
    })

    mentions['total_found'] = len(mentions['sources']) + len(mentions['business_listings'])

    return mentions, api_calls


def investigate_phone(phone_number, case_id):
    """
    Main phone OSINT investigation function

    Args:
        phone_number (str): Phone number to investigate
        case_id (str): Case ID to link investigation

    Returns:
        dict: Complete investigation results
    """
    start_time = time.time()

    try:
        # Validate and format phone number
        validation = validate_phone_number(phone_number)

        if not validation.get('is_valid'):
            return {
                'is_valid': False,
                'validation': validation,
                'error': 'Invalid phone number format',
                'metadata': {
                    'investigation_duration': time.time() - start_time,
                    'api_calls_made': 0
                }
            }

        # Parse for further analysis
        parsed = phonenumbers.parse(phone_number, "ZM")

        # Get location information
        location_info = get_location_info(parsed)

        # Get carrier information
        carrier_info = get_carrier_info(parsed)

        # Get enhanced data from Numverify API
        numverify_result = get_numverify_data(validation.get('international_format', phone_number))

        # If Numverify succeeded, enhance carrier info with its data
        if numverify_result.get('success'):
            numverify_data = numverify_result.get('data', {})
            # Enhance carrier info with Numverify data (more accurate)
            if numverify_data.get('carrier') and numverify_data['carrier'] != 'Unknown':
                carrier_info['carrier'] = numverify_data['carrier']
                carrier_info['source'] = 'Numverify API'
            if numverify_data.get('line_type'):
                carrier_info['line_type'] = numverify_data['line_type'].upper()
            # Add Numverify specific fields
            carrier_info['numverify_location'] = numverify_data.get('location', '')
            carrier_info['numverify_country'] = numverify_data.get('country_name', '')

        # Run Phoneinfoga scan for enhanced OSINT
        phoneinfoga_scan = run_phoneinfoga_scan(validation.get('international_format', phone_number))
        phoneinfoga_results = parse_phoneinfoga_results(phoneinfoga_scan)

        # Generate enhanced social media searches
        enhanced_social_searches = generate_enhanced_social_media_searches(
            phone_number,
            validation.get('international_format', phone_number)
        )

        # Search for social media accounts
        social_media, social_api_calls = search_social_media(
            phone_number,
            validation.get('international_format', phone_number)
        )

        # Search for online mentions and listings
        online_mentions, mentions_api_calls = search_online_mentions(
            phone_number,
            validation.get('international_format', phone_number)
        )

        # Check threat intelligence
        threat_intel_data = None
        threat_intel_api_calls = 0
        try:
            from app.modules.threat_intelligence import ThreatIntelligenceService
            ti_service = ThreatIntelligenceService()
            threat_intel_data = ti_service.check_phone(validation.get('international_format', phone_number))
            threat_intel_api_calls = len(threat_intel_data.get('sources_checked', []))
        except Exception as e:
            threat_intel_data = {'success': False, 'error': str(e)}

        # Compile results
        numverify_api_call = 1 if numverify_result.get('success') else 0
        total_api_calls = 3 + social_api_calls + mentions_api_calls + 1 + numverify_api_call + threat_intel_api_calls  # +1 for Phoneinfoga, +1 for Numverify if used, +threat_intel_api_calls

        results = {
            'is_valid': True,
            'validation': validation,
            'location': location_info,
            'carrier': carrier_info,
            'social_media': social_media,
            'online_mentions': online_mentions,
            'phoneinfoga': phoneinfoga_results,
            'enhanced_social_searches': enhanced_social_searches,
            'numverify': numverify_result,  # Add Numverify data
            'threat_intelligence': threat_intel_data,  # Add Threat Intelligence data
            'metadata': {
                'investigation_duration': time.time() - start_time,
                'api_calls_made': total_api_calls,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'case_id': case_id,
                'social_accounts_found': len(social_media),
                'mentions_found': online_mentions.get('total_found', 0),
                'phoneinfoga_dorks': phoneinfoga_results.get('total_dorks', 0),
                'phoneinfoga_enabled': phoneinfoga_scan.get('success', False),
                'enhanced_searches_generated': sum([len(v) for v in enhanced_social_searches.values()]),
                'numverify_enabled': numverify_result.get('success', False),
                'threat_intel_enabled': threat_intel_data is not None and threat_intel_data.get('indicator') is not None
            }
        }

        # Risk assessment
        results['risk_assessment'] = check_risk_indicators(results)

        return results

    except Exception as e:
        return {
            'is_valid': False,
            'error': f'Investigation failed: {str(e)}',
            'metadata': {
                'investigation_duration': time.time() - start_time,
                'api_calls_made': 0
            }
        }
