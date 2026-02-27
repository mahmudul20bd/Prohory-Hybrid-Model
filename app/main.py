from fastapi import FastAPI, Body  # Body ইম্পোর্ট করা হলো
from pydantic import BaseModel
# from app.celery_worker import background_scan_task  # এটি পরে কাজে লাগবে
from app.scanner import process_message_hybrid, analyze_with_huggingface # analyze_with_huggingface ইম্পোর্ট করা হলো

app = FastAPI(title="Prohory Scanner Microservice", version="2.0")

# Spring Boot থেকে আসা রিকোয়েস্টের মডেল
class ScanRequestSync(BaseModel):
    message: str

@app.head("/")
@app.get("/")
def read_root():
    return {"status": "Prohory API is running perfectly."}

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