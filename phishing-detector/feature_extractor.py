import re
import math
from urllib.parse import urlparse
from tldextract import extract as tld_extract

SUSPICIOUS_TLDS = {'tk','xyz','top','zip','ml','ga','cf','gq','work','click','country'}
SHORTENERS = {'bit.ly','tinyurl','goo.gl','t.co','ow.ly','is.gd'}
BRANDS = ['paypal','apple','microsoft','google','amazon','netflix','facebook',
          'instagram','whatsapp','bank','dhl','fedex','linkedin','outlook']

def entropy(s):
    if not s: return 0
    p = [s.count(c)/len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p)

def extract_features(url):
    parsed = urlparse(url)
    host, path = parsed.netloc, parsed.path
    ext = tld_extract(url)
    brand_in_sub = 0
    for b in BRANDS:
        if b in ext.subdomain.lower() and b not in ext.domain.lower():
            brand_in_sub = 1; break
    return {
        'url_length': len(url), 'host_length': len(host), 'path_length': len(path),
        'num_dots': url.count('.'), 'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'), 'num_digits': sum(c.isdigit() for c in url),
        'num_special': sum(c in '@?=&%#;' for c in url), 'num_slashes': url.count('/'),
        'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'has_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', host))),
        'has_at': int('@' in url), 'is_https': int(parsed.scheme == 'https'),
        'entropy': entropy(url), 'digit_ratio': sum(c.isdigit() for c in url)/len(url),
        'special_ratio': sum(c in '@?=&%#;' for c in url)/len(url),
        'suspicious_tld': int(ext.suffix.lower() in SUSPICIOUS_TLDS),
        'shortener': int(any(s in host.lower() for s in SHORTENERS)),
        'has_port': int(bool(parsed.port)), 'path_depth': path.count('/'),
        'query_length': len(parsed.query), 'num_query_params': parsed.query.count('='),
        'brand_in_subdomain': brand_in_sub,
    }