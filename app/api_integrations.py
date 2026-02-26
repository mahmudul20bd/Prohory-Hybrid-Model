import os
import requests
import base64
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright  # নতুন ইমপোর্ট

load_dotenv()

GSB_API_KEY = os.getenv("GSB_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

def check_google_safe_browsing(url: str) -> str:
    """Step 3: Google Safe Browsing (GSB) Fast Check"""
    if not GSB_API_KEY:
        return "SAFE" # API Key না থাকলে আপাতত বাইপাস করবে

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "prohory_microservice", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        if response.status_code == 200 and "matches" in response.json():
            return "DANGER"
        return "SAFE"
    except Exception as e:
        print(f"GSB Error: {e}")
        return "SAFE"

def check_virustotal_v3(url: str) -> dict:
    """Step 6 Fallback: VirusTotal API V3 Check"""
    if not VT_API_KEY:
        return {"status": "SAFE", "details": "No API Key"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                return {"status": "DANGER", "stats": stats}
        return {"status": "SAFE", "stats": {}}
    except Exception as e:
        print(f"VirusTotal Error: {e}")
        return {"status": "ERROR"}

def fetch_page_content(url: str) -> str:
    """
    Step 5: Deep Web Scraping with Headless Browser (Playwright)
    জাভাস্ক্রিপ্ট রান হওয়ার পর পেজের আসল টেক্সট স্ক্র্যাপ করা (Cloudflare / JS Loaders বাইপাস)
    """
    try:
        # Playwright দিয়ে অদৃশ্য ব্রাউজার চালু করা
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) # headless=True মানে ব্রাউজার স্ক্রিনে দেখা যাবে না
            page = browser.new_page()
            
            # সাইটে যাওয়া এবং জাভাস্ক্রিপ্ট লোড হওয়া পর্যন্ত (networkidle) অপেক্ষা করা
           # networkidle এর বদলে domcontentloaded দেওয়া হলো, যাতে বেসিক পেজ লোড হলেই স্ক্র্যাপ করে ফেলে
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            
            # জাভাস্ক্রিপ্ট রেন্ডার হওয়ার পর আসল HTML সোর্স কোডটি নিয়ে আসা
            html_content = page.content()
            browser.close()

            # এরপর BeautifulSoup দিয়ে শুধু মানুষের পড়ার মতো টেক্সটগুলো (Visible Text) ফিল্টার করা
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.title.string if soup.title else ""
            
            for script in soup(["script", "style", "noscript"]):
                script.extract()

            visible_text = soup.get_text(separator=' ', strip=True)
            
            # টেক্সট খুব বড় হলে প্রথম ৫০০০ ক্যারেক্টার নেব, যাতে AI মডেল ওভারলোড না হয়
            combined_text = f"{title} {visible_text}"[:5000] 
            return combined_text
            
    except Exception as e:
        print(f"Playwright Scraping Error for {url}: {e}")
        return ""