import os
import requests
import base64
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright
import pytesseract
from PIL import Image

load_dotenv()

GSB_API_KEY = os.getenv("GSB_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

def check_google_safe_browsing(url: str) -> str:
    """Step 3: Google Safe Browsing (GSB) Fast Check"""
    if not GSB_API_KEY or "your_" in GSB_API_KEY:
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
    if not VT_API_KEY or "your_" in VT_API_KEY:
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

def fetch_page_content_advanced(url: str) -> dict:
    """
    Step 5: Playwright দিয়ে পেজ স্ক্র্যাপ, রিডাইরেক্ট চেইন, ফর্ম ডিটেকশন এবং OCR
    """
    result = {
        "text": "",
        "has_password_form": False,
        "redirect_count": 0,
        "final_url": url,
        "ocr_used": False
    }
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            page = context.new_page()

            # 1. Redirect Tracking (রিডাইরেক্ট চেইন ধরা)
            redirects = []
            page.on("request", lambda request: redirects.append(request.redirected_from) if request.redirected_from else None)

            # পেজে যাওয়া
            response = page.goto(url, timeout=15000, wait_until="domcontentloaded")
            
            result["redirect_count"] = len(redirects)
            result["final_url"] = page.url

            # 2. Form & Password Trap Detection (ফিশিং চেক)
            password_inputs = page.locator("input[type='password']").count()
            if password_inputs > 0:
                result["has_password_form"] = True

            # HTML থেকে টেক্সট বের করা
            html_content = page.content()
            soup = BeautifulSoup(html_content, "html.parser")
            
            for script_or_style in soup(['script', 'style', 'header', 'footer', 'nav']):
                script_or_style.decompose()
                
            visible_text = soup.get_text(separator=' ', strip=True)
            
            # 3. Vision AI / OCR Logic (পেজ ফাঁকা হলে বা শুধু ছবি থাকলে)
            if len(visible_text) < 50:  
                print(f"Page seems empty. Triggering OCR for {url}...")
                screenshot_path = "temp_screenshot.png"
                page.screenshot(path=screenshot_path)
                
                try:
                    ocr_text = pytesseract.image_to_string(Image.open(screenshot_path), lang='eng+ben')
                    visible_text = visible_text + " " + ocr_text
                    result["ocr_used"] = True
                except Exception as ocr_err:
                    print(f"OCR Failed: {ocr_err}")
                finally:
                    if os.path.exists(screenshot_path):
                        os.remove(screenshot_path)

            result["text"] = visible_text[:3000] # প্রথম ৩০০০ অক্ষর রাখব
            browser.close()
            return result
            
    except Exception as e:
        print(f"Advanced Scraping Error for {url}: {e}")
        return result