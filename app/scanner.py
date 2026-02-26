import os
import requests
import logging
from dotenv import load_dotenv

from app.utils import (
    extract_urls, unshorten_url, get_domain_age_risk, 
    is_whitelisted, check_typosquatting, check_ssl_risk
)
from app.api_integrations import (
    check_google_safe_browsing, check_virustotal_v3, fetch_page_content_advanced
)

# লগিং সেটআপ করা (Render-এ প্রফেশনাল লগ দেখার জন্য)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ProhoryScanner")

load_dotenv()

def analyze_with_huggingface(text: str) -> float:
    """Step 1 & Step 6: CyberAware HF Space API Integration"""
    HF_API_URL = os.getenv("HF_API_URL")
    
    if not HF_API_URL or "hf.space" not in HF_API_URL:
        logger.warning("Real API URL missing. Returning dummy score.")
        return 0.75 

    payload = {"message": text}
    
    try:
        response = requests.post(HF_API_URL, json=payload, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            result_label = str(data.get("result", "")).upper()
            raw_confidence = data.get("confidence", 0.0)
            
            # String percentage fix
            if isinstance(raw_confidence, str):
                clean_str = raw_confidence.replace('%', '').strip()
                confidence = float(clean_str) / 100.0  
            else:
                confidence = float(raw_confidence)
                if confidence > 1.0:
                    confidence = confidence / 100.0
            
            logger.info(f"HF Space API Response -> Result: {result_label}, Confidence: {confidence:.2f}")
            
            if result_label in ["SPAM", "DANGER", "SUSPICIOUS"]:
                return confidence
            else:
                return 0.0 
        else:
            logger.error(f"HF Space API Error ({response.status_code}): {response.text}")
            return 0.0
    except Exception as e:
        logger.error(f"HF Space Connection Error: {e}")
        return 0.0
    

def process_message_hybrid(message: str) -> dict:
    """আল্ট্রা-অ্যাডভান্সড প্রহরী স্ক্যানিং ইঞ্জিন (Version 2.0)"""
    
    # Step 1: Initial AI Scan
    initial_score = analyze_with_huggingface(message)
    urls = extract_urls(message)
    
    # মেসেজে লিংক না থাকলে শুধু AI এর কথার ওপর ভিত্তি করে রেজাল্ট
    if not urls:
        # *** OTP Bypass Logic ***
        lower_msg = message.lower()
        if "otp" in lower_msg or "ওটিপি" in lower_msg or "code" in lower_msg:
            logger.info("📩 Detected as standard OTP message. Bypassing AI suspicion.")
            return {
                "final_verdict": "SAFE", 
                "ai_confidence": initial_score, 
                "details": "OTP Message (No links)"
            }

        status = "DANGER" if initial_score >= 0.70 else "SAFE"
        return {"final_verdict": status, "ai_confidence": initial_score, "details": "Text only analysis"}

    results = []
    is_danger_found = False

    for url in urls:
        real_url = unshorten_url(url)
        
        # 0. Global Whitelist Check
        if is_whitelisted(real_url):
            logger.info(f"✅ [{real_url}] is a Trusted Domain. Bypassing security checks.")
            results.append({"url": real_url, "status": "SAFE", "reason": "Trusted Global Whitelist Domain"})
            continue
            
        # *** 0.5. Typosquatting (Brand Clone) Check ***
        typo_check = check_typosquatting(real_url)
        if typo_check["is_typosquat"]:
            brand = typo_check["brand"]
            logger.warning(f"🎭 Typosquatting Detected: {real_url} is faking {brand}")
            results.append({
                "url": real_url, 
                "status": "DANGER", 
                "reason": f"Brand Impersonation! Trying to fake '{brand}'"
            })
            is_danger_found = True
            continue 
        
        # 1. WHOIS Risk Check 
        whois_data = get_domain_age_risk(real_url)
        if whois_data['risk'] == "HIGH":
            logger.warning(f"⚠️ Suspiciously new domain detected: {real_url}")
            results.append({"url": real_url, "status": "DANGER", "reason": f"Suspiciously new domain. {whois_data['message']}"})
            is_danger_found = True
            continue
            
        # *** 1.5. SSL Risk Check ***
        ssl_data = check_ssl_risk(real_url)
        if ssl_data.get("is_free_cert"):
            logger.warning(f"🔓 Free/Suspicious SSL Certificate detected for {real_url}")
            
        # 2. Google Safe Browsing (GSB) Check
        gsb_status = check_google_safe_browsing(real_url)
        if gsb_status == "DANGER":
            logger.warning(f"🛑 Flagged by Google Safe Browsing: {real_url}")
            results.append({"url": real_url, "status": "DANGER", "reason": "Flagged by Google Safe Browsing"})
            is_danger_found = True
            continue
            
        # 3. Conflict Resolution & Deep Scraping (Advanced)
        if gsb_status == "SAFE" and initial_score >= 0.70:
            
            if initial_score >= 0.90:
                logger.warning(f"🚨 [Direct Block] High AI Confidence ({initial_score}) for {real_url}. Skipping scraping!")
                results.append({"url": real_url, "status": "DANGER", "reason": f"Definitive malicious text detected (AI Score: {initial_score}). Link blocked."})
                is_danger_found = True
                continue

            logger.info(f"🔍 Model suspects the message (Score: {initial_score}). Triggering Advanced Deep Scraping for {real_url}...")
            scraped_data = fetch_page_content_advanced(real_url)
            scraped_text = scraped_data.get("text", "")
            
            # *** Phishing Trap Detection ***
            if scraped_data.get("has_password_form") and (initial_score >= 0.75 or ssl_data.get("is_free_cert")):
                logger.warning(f"🎣 Phishing Trap Detected for {real_url}: Password form found on suspicious site!")
                results.append({"url": real_url, "status": "DANGER", "reason": "Phishing Trap! Password form found on suspicious/untrusted site."})
                is_danger_found = True
                continue

            if scraped_text:
                second_score = analyze_with_huggingface(scraped_text)
                logger.info(f"🧠 Second AI Scan on Page Content -> Score: {second_score} (OCR Used: {scraped_data.get('ocr_used')})")
                
                if second_score >= 0.70:
                    reason = "Hidden Threat detected on page content"
                    if scraped_data.get("ocr_used"):
                        reason += " (detected via OCR Image Analysis)"
                    
                    logger.warning(f"🦠 Hidden Threat Confirmed by AI on {real_url}")
                    results.append({"url": real_url, "status": "DANGER", "reason": reason})
                    is_danger_found = True
                    continue
                else:
                    logger.info(f"🛡️ Initial prediction was a False Positive. The page {real_url} is actually safe.")
            else:
                logger.warning(f"⏳ Scraping failed or timed out for {real_url}.")
                results.append({"url": real_url, "status": "DANGER", "reason": "Suspicious message and site is unresponsive/hidden."})
                is_danger_found = True
                continue

        # 4. Fallback: VirusTotal
        vt_result = check_virustotal_v3(real_url)
        if vt_result.get("status") == "DANGER":
            logger.warning(f"🕷️ Detected by VirusTotal fallback: {real_url}")
            results.append({"url": real_url, "status": "DANGER", "reason": "Detected by VirusTotal fallback"})
            is_danger_found = True
            continue
        
        # সব টেস্ট পাস করলে লিংকটি সেফ
        results.append({"url": real_url, "status": "SAFE", "reason": "Passed all security layers"})

    final_status = "DANGER" if is_danger_found else "SAFE"
    
    return {
        "final_verdict": final_status,
        "ai_confidence": initial_score,
        "link_analysis": results
    }