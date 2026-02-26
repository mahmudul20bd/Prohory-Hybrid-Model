import re
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
import difflib

def extract_urls(text: str) -> list:
    """মেসেজ থেকে URL খুঁজে বের করার আপডেটেড রেগুলার এক্সপ্রেশন"""
    url_pattern = re.compile(r'(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')
    urls = url_pattern.findall(text)
    
    clean_urls = []
    for url in urls:
        clean_url = url.rstrip('.,।!?"\'')
        clean_urls.append(clean_url)
        
    return clean_urls

def unshorten_url(url: str, timeout: int = 5) -> str:
    """শর্ট লিংক (bit.ly, cutt.ly) থেকে আসল গন্তব্য বের করা"""
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        response = requests.get(url, allow_redirects=True, timeout=timeout)
        real_url = response.url
        
        # Meta refresh check (Deep Decrypt)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                split_content = re.split('url=', content, flags=re.IGNORECASE)
                if len(split_content) > 1:
                    return split_content[1].strip('\'"')
        return real_url
    except Exception as e:
        print(f"Unshorten Error: {e}")
        return url

def get_domain_age_risk(url: str) -> dict:
    try:
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]
            
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if not creation_date:
            return {"risk": "HIGH", "age_days": 0, "message": "Hidden WHOIS data"}

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.now() - creation_date).days
        
        if age_days < 30:
            return {"risk": "HIGH", "age_days": age_days, "message": f"Very new domain ({age_days} days old)"}
        elif age_days < 180:
            return {"risk": "MEDIUM", "age_days": age_days, "message": f"Relatively new domain ({age_days} days old)"}
        else:
            return {"risk": "LOW", "age_days": age_days, "message": f"Established domain ({age_days} days old)"}
            
    except Exception as e:
        print(f"WHOIS Error for {url}: {e}")
        return {"risk": "UNKNOWN", "age_days": -1, "message": "Failed to fetch domain age"}

# বিশ্বের সবচেয়ে পরিচিত ও নিরাপদ ওয়েবসাইটগুলোর তালিকা
WHITELIST_DOMAINS = {
    "zoom.us", "google.com", "youtube.com", "facebook.com", 
    "microsoft.com", "github.com", "linkedin.com", "meet.google.com",
    "bkash.com", "nagad.com.bd"
}

def is_whitelisted(url: str) -> bool:
    """চেক করবে লিংকটি ট্রাস্টেড ডোমেইন কি না (সাব-ডোমেইন সহ)"""
    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
            
        for wl_domain in WHITELIST_DOMAINS:
            if domain == wl_domain or domain.endswith("." + wl_domain):
                return True
        return False
    except:
        return False

def check_typosquatting(url: str) -> dict:
    """ব্র্যান্ড ক্লোনিং বা টাইপোকোয়াটিং চেক"""
    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        
        domain_name = domain.split('.')[0]

        for brand in WHITELIST_DOMAINS:
            brand_name = brand.split('.')[0]
            similarity = difflib.SequenceMatcher(None, domain_name, brand_name).ratio()
            
            if similarity >= 0.80 and domain != brand and not domain.endswith("." + brand):
                return {"is_typosquat": True, "brand": brand, "similarity": similarity}
                
        return {"is_typosquat": False}
    except:
        return {"is_typosquat": False}

def check_ssl_risk(url: str) -> dict:
    """SSL সার্টিফিকেটের ধরন এবং বয়স চেক"""
    try:
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_org = issuer.get('organizationName', '').lower()
                
                # Let's Encrypt বা ZeroSSL ফ্রি সার্টিফিকেট স্ক্যামাররা বেশি ব্যবহার করে
                is_free_cert = "let's encrypt" in issuer_org or "zero ssl" in issuer_org
                
                return {"success": True, "is_free_cert": is_free_cert, "issuer": issuer_org}
    except Exception as e:
        return {"success": False, "error": str(e)}