# ── feature_extractor.py ──
import re
import math
from urllib.parse import urlparse
from tldextract import extract as tld_extract
from Levenshtein import distance as lev_dist

# ============ CONFIG ============
SUSPICIOUS_TLDS = {'tk','xyz','top','zip','ml','ga','cf','gq','work','click','country'}
SHORTENERS = {'bit.ly','tinyurl','goo.gl','t.co','ow.ly','is.gd'}
BRANDS = ['google','paypal','apple','microsoft','amazon','netflix','facebook',
          'instagram','whatsapp','bank','dhl','fedex','linkedin','outlook',
          'youtube','twitter','dropbox','adobe','wellsfargo','chase','citibank']

# WHITELIST — top legit domains the model should NEVER flag as phishing
WHITELIST = {
    'google.com','facebook.com','amazon.com','youtube.com','twitter.com',
    'wikipedia.org','apple.com','microsoft.com','netflix.com','linkedin.com',
    'instagram.com','openai.com','github.com','stackoverflow.com','reddit.com',
    'whatsapp.com','dropbox.com','adobe.com','wellsfargo.com','chase.com',
    'citibank.com','paypal.com','dhl.com','fedex.com','outlook.com',
    'python.org','mozilla.org','w3.org','apache.org','gnu.org','linux.org',
    'un.org','who.int','nih.gov','nasa.gov','mit.edu','stanford.edu',
}

# ============ HELPERS ============
def entropy(s):
    if not s: return 0
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p)

def normalize_homoglyphs(s):
    return (s.lower()
            .replace('0','o').replace('1','l').replace('3','e')
            .replace('4','a').replace('5','s').replace('@','a')
            .replace('rn','m'))

def min_brand_distance(domain):
    """Min Levenshtein distance to nearest brand, checking hyphen-split segments."""
    d = domain.lower()
    if not d: return 99
    parts = d.replace('-', ' ').replace('_', ' ').split()
    if not parts:
        parts = [d]
    min_dist = 99
    for part in parts:
        for b in BRANDS:
            dist = lev_dist(part, b)
            if dist < min_dist:
                min_dist = dist
    return min_dist

def brand_after_normalization(domain):
    dl = domain.lower()
    if dl in BRANDS: return 0
    norm = normalize_homoglyphs(domain)
    return int(any(b in norm for b in BRANDS))

def is_exact_brand(domain):
    return int(domain.lower() in BRANDS)

def is_whitelisted(domain, suffix=''):
    full = f"{domain.lower()}.{suffix.lower()}" if suffix else domain.lower()
    return int(full in WHITELIST or domain.lower() in WHITELIST)

# ============ MAIN EXTRACTOR ============
def extract_features(url):
    parsed = urlparse(url)
    host, path = parsed.netloc, parsed.path
    ext = tld_extract(url)
    host_lower = host.lower()

    brand_in_sub = 0
    for b in BRANDS:
        if b in ext.subdomain.lower() and b not in ext.domain.lower():
            brand_in_sub = 1
            break

    return {
        'url_length': len(url),
        'host_length': len(host),
        'path_length': len(path),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special': sum(c in '@?=&%#;' for c in url),
        'num_slashes': url.count('/'),
        'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'has_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', host))),
        'has_at': int('@' in url),
        'is_https': int(parsed.scheme == 'https'),
        'entropy': entropy(url),
        'digit_ratio': sum(c.isdigit() for c in url) / len(url),
        'special_ratio': sum(c in '@?=&%#;' for c in url) / len(url),
        'suspicious_tld': int(ext.suffix.lower() in SUSPICIOUS_TLDS),
        'shortener': int(any(s in host_lower for s in SHORTENERS)),
        'has_port': int(bool(parsed.port)),
        'brand_in_subdomain': brand_in_sub,
        'path_depth': path.count('/'),
        'query_length': len(parsed.query),
        'num_query_params': parsed.query.count('='),
        'min_brand_dist': min_brand_distance(ext.domain),
        'homoglyph_brand_match': brand_after_normalization(ext.domain),
        'is_exact_brand': is_exact_brand(ext.domain),
        'is_whitelisted': is_whitelisted(ext.domain, ext.suffix),
    }
