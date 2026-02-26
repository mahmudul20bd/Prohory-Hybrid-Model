import os
from dotenv import load_dotenv
from app.utils import extract_urls, unshorten_url, get_domain_age_risk
from app.api_integrations import check_google_safe_browsing, check_virustotal_v3, fetch_page_content
from app.utils import extract_urls, unshorten_url, get_domain_age_risk, is_whitelisted

load_dotenv()

import os
import requests
from dotenv import load_dotenv

load_dotenv()

def analyze_with_huggingface(text: str) -> float:
    """
    Step 1 & Step 6: CyberAware HF Space API Integration
    স্ট্রিং পার্সেন্টেজ ("100.00%") ফিক্স করা হয়েছে।
    """
    HF_API_URL = os.getenv("HF_API_URL")
    
    if not HF_API_URL or "hf.space" not in HF_API_URL:
        print("Warning: Real API URL missing. Returning dummy score.")
        return 0.75 

    payload = {"message": text}
    
    try:
        response = requests.post(HF_API_URL, json=payload, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            result_label = str(data.get("result", "")).upper()
            raw_confidence = data.get("confidence", 0.0)
            
            # 100.00% বা স্ট্রিং ফরম্যাটকে 0.0 - 1.0 স্কেলে কনভার্ট করার লজিক
            if isinstance(raw_confidence, str):
                clean_str = raw_confidence.replace('%', '').strip()
                confidence = float(clean_str) / 100.0  # 100.00 হবে 1.0
            else:
                confidence = float(raw_confidence)
                if confidence > 1.0:
                    confidence = confidence / 100.0
            
            print(f"HF Space API Response -> Result: {result_label}, Confidence: {confidence:.2f}")
            
            if result_label in ["SPAM", "DANGER", "SUSPICIOUS"]:
                return confidence
            else:
                return 0.0 
            
        else:
            print(f"HF Space API Error ({response.status_code}): {response.text}")
            return 0.0
            
    except Exception as e:
        print(f"HF Space Connection Error: {e}")
        return 0.0
    
def process_message_hybrid(message: str) -> dict:
    # Step 1: Initial AI Scan
    initial_score = analyze_with_huggingface(message)
    urls = extract_urls(message)
    
    # মেসেজে লিংক না থাকলে শুধু AI এর কথার ওপর ভিত্তি করে রেজাল্ট
    if not urls:
        status = "DANGER" if initial_score >= 0.70 else "SAFE"
        return {"final_verdict": status, "ai_confidence": initial_score, "details": "Text only analysis"}

    # *** এই দুটি লাইন লুপের আগে থাকতেই হবে! ***
    results = []
    is_danger_found = False

    for url in urls:
        real_url = unshorten_url(url)
        
        # 0. Global Whitelist Check (The Fix)
        if is_whitelisted(real_url):
            print(f"[{real_url}] is a Trusted Domain. Bypassing security checks.")
            results.append({"url": real_url, "status": "SAFE", "reason": "Trusted Global Whitelist Domain"})
            continue
        
        # 1. WHOIS Risk Check 
        whois_data = get_domain_age_risk(real_url)
        if whois_data['risk'] == "HIGH":
            results.append({"url": real_url, "status": "DANGER", "reason": f"Suspiciously new domain. {whois_data['message']}"})
            is_danger_found = True
            continue
            
        # 2. Google Safe Browsing (GSB) Fast Check
        gsb_status = check_google_safe_browsing(real_url)
        if gsb_status == "DANGER":
            results.append({"url": real_url, "status": "DANGER", "reason": "Flagged by Google Safe Browsing"})
            is_danger_found = True
            continue
            
        # 3. Conflict Resolution & Deep Scraping
        if gsb_status == "SAFE" and initial_score >= 0.70:
            
            # The Ultimate Trust Logic
            if initial_score >= 0.90:
                results.append({"url": real_url, "status": "DANGER", "reason": f"Definitive malicious text detected (AI Score: {initial_score}). Link blocked."})
                is_danger_found = True
                continue

            print(f"Model suspects the message (Score: {initial_score}). Triggering Deep Scraping...")
            scraped_text = fetch_page_content(real_url)
            
            if scraped_text:
                second_score = analyze_with_huggingface(scraped_text)
                print(f"Second AI Scan on Page Content -> Score: {second_score}")
                
                if second_score >= 0.70:
                    results.append({"url": real_url, "status": "DANGER", "reason": "Hidden Threat detected on page content"})
                    is_danger_found = True
                    continue
                else:
                    print("Initial prediction was a False Positive. The page is actually safe.")
            else:
                print("Scraping failed or timed out.")
                results.append({"url": real_url, "status": "DANGER", "reason": "Suspicious message and site is unresponsive/hidden."})
                is_danger_found = True
                continue

        # 4. Fallback: VirusTotal
        vt_result = check_virustotal_v3(real_url)
        if vt_result.get("status") == "DANGER":
            results.append({"url": real_url, "status": "DANGER", "reason": "Detected by VirusTotal fallback"})
            is_danger_found = True
            continue
        
        # সব টেস্ট পাস করলে বা AI এর সেকেন্ড স্ক্যান সেফ বললে
        results.append({"url": real_url, "status": "SAFE", "reason": "Passed all security layers"})

    # ফাইনাল ভার্ডিক্ট: লিংকগুলোর যেকোনো একটি যদি DANGER হয়, তবেই পুরো মেসেজ DANGER
    final_status = "DANGER" if is_danger_found else "SAFE"
    
    return {
        "final_verdict": final_status,
        "ai_confidence": initial_score,
        "link_analysis": results
    }