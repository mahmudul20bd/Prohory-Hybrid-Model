# Playwright-এর অফিশিয়াল পাইথন ইমেজ (যেখানে আগে থেকেই লিনাক্স আর ব্রাউজার সেটআপ করা থাকে)
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

# প্রজেক্টের র্ওয়ার্কিং ডিরেক্টরি সেট করা
WORKDIR /code

# রিকোয়ারমেন্টস কপি করে ইনস্টল করা
COPY requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir -r /code/requirements.txt

# Playwright এর ব্রাউজার ইনস্টল করা
RUN playwright install chromium

# প্রজেক্টের সব ফাইল সার্ভারে কপি করা
COPY . /code/

# FastAPI সার্ভার চালু করার কমান্ড (Render অটোমেটিক পোর্ট অ্যাসাইন করবে)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]