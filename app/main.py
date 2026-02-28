from fastapi import FastAPI, Body, File, UploadFile
from pydantic import BaseModel
import pytesseract
from PIL import Image
import io
# from app.celery_worker import background_scan_task  # এটি পরে কাজে লাগবে
from app.scanner import process_message_hybrid, analyze_with_huggingface

app = FastAPI(title="Prohory Scanner Microservice", version="3.0")

# Spring Boot থেকে আসা রিকোয়েস্টের মডেল
class ScanRequestSync(BaseModel):
    message: str

@app.head("/")
@app.get("/")
def read_root():
    return {"status": "Prohory API is running perfectly at Level-5."}

@app.post("/api/v1/scan-ai")
async def scan_ai_only(payload: dict = Body(...)):
    """
    শুধুমাত্র AI ডিসিশন (SAFE/PROMO/SPAM/DANGER) রিটার্ন করার জন্য ডেডিকেটেড এন্ডপয়েন্ট।
    এটি Spring Boot-এর Thread-1 থেকে কল করা হবে।
    """
    message = payload.get("message", "")
    
    # AI মডেল থেকে সরাসরি লেবেল এবং কনফিডেন্স নিয়ে আসা
    ai_result = analyze_with_huggingface(message)
    
    return {
        "label": ai_result["label"],
        "ai_confidence": ai_result["confidence"]
    }

@app.post("/api/v1/scan-sync")
def test_scan_sync(request: ScanRequestSync):
    """
    সরাসরি টেস্টিংয়ের জন্য (Redis/Celery ছাড়া)।
    এটি রিকোয়েস্ট পাওয়ার সাথে সাথে স্ক্যান করে ফাইনাল রেজাল্ট রিটার্ন করবে।
    """
    scan_result = process_message_hybrid(request.message)
    return scan_result

# =================================================================
# 🚀 NEW: OCR Threat Analyzer Endpoint (Level-5 Upgrade)
# =================================================================
@app.post("/api/v1/scan-ocr")
async def scan_image_ocr(file: UploadFile = File(...)):
    """
    এই এন্ডপয়েন্টটি Spring Boot থেকে ইমেজ রিসিভ করবে, 
    সেখান থেকে টেক্সট বের করবে (OCR) এবং সাথে সাথে AI মডেল দিয়ে স্ক্যান করে রেজাল্ট দেবে।
    """
    try:
        # ১. ইমেজ রিড করা
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))
        
        # ২. Tesseract OCR দিয়ে ইমেজ থেকে টেক্সট বের করা (Bangla + English সাপোর্ট)
        # খেয়াল করুন: সার্ভারে tesseract-ocr-ben ইন্সটল থাকতে হবে
        extracted_text = pytesseract.image_to_string(image, lang='eng+ben')
        
        # ৩. টেক্সট ক্লিন করা (অতিরিক্ত স্পেস বা লাইন ব্রেক মুছে ফেলা)
        clean_text = " ".join(extracted_text.split())
        
        if not clean_text:
            return {
                "extracted_text": "", 
                "label": "SAFE", 
                "ai_confidence": 1.0, 
                "status": "No text found in image"
            }

        # ৪. বের করা টেক্সটকে Main AI (HuggingFace) দিয়ে অ্যানালাইজ করা
        ai_result = analyze_with_huggingface(clean_text)
        
        return {
            "extracted_text": clean_text,
            "label": ai_result["label"],
            "ai_confidence": ai_result["confidence"],
            "status": "success"
        }
    except Exception as e:
        return {"error": str(e), "status": "failed"}