"""
URL feature extraction for phishing detection.
"""
import pandas as pd
import re
from urllib.parse import urlparse


def extract_url_features(url):
    features = {}
    try:
        if pd.isna(url) or not isinstance(url, str):
            raise ValueError("Invalid URL")

        # Parse the url
        parsed = urlparse(url)
        domain = parsed.netloc  # gets the domain, to check if there is an
        # IP address instead of a domain
        path = parsed.path      # gets the path, to check if it's trying
        # to mimic a legit site
        query = parsed.query    # gets what is after the ?, to check if
        # the query is too long or has weird parameters

        # Checks if the domain looks like an IP address in ipv4, ipv6 or
        # hexadecimal format. If so there is more likelihood it is phishing
        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        ipv6_pattern = r"^\[?([a-fA-F0-9:]+)\]?$"
        hex_pattern = r"^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$"
        features['has_ip_address'] = int(bool(
            re.match(ipv4_pattern, domain) or
            re.match(ipv6_pattern, domain) or
            re.search(hex_pattern, domain)
        ))

        # Check on the length: 0-54 likely safe, 54-75 watchful, 75+
        # suspicious. Based on research, long URLs are usually phishing.
        length = len(url)
        features['url_length_category'] = 0 if length < 54 else 1 if length <= 75 else 2

        # 1 if the URL used a shortening service, 0 if not
        shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
                                "t.co", "is.gd", "buff.ly", "adf.ly",
                                "bit.do", "mcaf.ee"]
        features['uses_shortening_service'] = int(
            any(service in url for service in shortening_services)
        )

        # @ is a sign of a phishing url
        features['has_at_symbol'] = int("@" in url)

        # // sign of a phishing url
        features['double_slash_position'] = int(url.rfind("//") > 7)

        # - sign of a phishing url
        features['prefix_suffix_in_domain'] = int("-" in domain)

        # Number of subdomains
        dot_count = domain.count(".")
        features['subdomain_level'] = 0 if dot_count == 1 else 1 if dot_count == 2 else 2

        # Checks if the word "https" is found in the domain
        features['https_token_in_domain'] = int("https" in domain.lower())

        # Number of digits in the url, if too many, phishing
        features['num_digits'] = sum(c.isdigit() for c in url)

        # Too many special characters, phishing
        features['num_special_chars'] = sum(c in "=?.%&#" for c in url)

        # How many = are in the query string
        features['num_parameters'] = query.count("=")

        # Checks for suspicious keywords
        suspicious_keywords = ['login', 'secure', 'verify', 'account',
                                'update', 'bank', 'signin', 'submit']
        features['has_suspicious_words'] = int(
            any(word in url.lower() for word in suspicious_keywords)
        )

        # Check if it is an executable
        features['ends_with_exe'] = int(url.lower().endswith(".exe"))

        # Counts http/https occurrences
        features['count_http_https'] = url.lower().count("http")

    except Exception:
        features = {
            'has_ip_address': 0,
            'url_length_category': 0,
            'uses_shortening_service': 0,
            'has_at_symbol': 0,
            'double_slash_position': 0,
            'prefix_suffix_in_domain': 0,
            'subdomain_level': 0,
            'https_token_in_domain': 0,
            'num_digits': 0,
            'num_special_chars': 0,
            'num_parameters': 0,
            'has_suspicious_words': 0,
            'ends_with_exe': 0,
            'count_http_https': 0,
        }

    return features