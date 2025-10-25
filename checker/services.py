import os
import re
import json
import requests
import openai
import bleach
import validators
import whois
import logging
from bs4 import BeautifulSoup
from datetime import datetime
from django.conf import settings
from openai import OpenAI

# ========== KONFIGURASI DASAR ==========

logger = logging.getLogger(__name__)
client = OpenAI(api_key=settings.OPENAI_API_KEY)
GOOGLE_API_KEY = settings.GOOGLE_SAFE_BROWSING_KEY

# ========== UTILITY DASAR ==========


def extract_url_from_message(text: str):
    """
    Mendeteksi URL pertama di pesan pengguna menggunakan regex.
    Mengembalikan string URL atau None jika tidak ditemukan.
    """
    url_pattern = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
    match = url_pattern.search(text)
    return match.group(0) if match else None


def sanitize_url(url: str):
    """
    Membersihkan dan memvalidasi URL dari pesan input.
    """
    if not url:
        return None

    clean = bleach.clean(url).strip()

    if not clean.startswith(("http://", "https://")):
        clean = "https://" + clean

    if validators.url(clean):
        return clean

    if not url.startswith(("http://", "https://")):
        clean_http = "http://" + bleach.clean(url).strip()
        if validators.url(clean_http):
            return clean_http

    return None

# ========== STEP 1: CEK GOOGLE SAFE BROWSING ==========


def check_google_safe_browsing(url: str):
    """
    Mengecek apakah URL terdaftar di database Google Safe Browsing.
    """
    try:
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "cekaman", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        res = requests.post(
            api_url, params={"key": GOOGLE_API_KEY}, json=payload, timeout=6
        )

        if res.status_code == 200:
            data = res.json()
            if "matches" in data and len(data["matches"]) > 0:
                return {
                    "is_dangerous": True,
                    "threat_type": data["matches"][0]["threatType"],
                }
            return {"is_dangerous": False, "threat_type": None}
        else:
            logger.warning(f"Google Safe Browsing Error {res.status_code}: {res.text}")
            return {"is_dangerous": None, "error": f"API Error {res.status_code}"}

    except Exception as e:
        logger.error(f"Google Safe Browsing Exception: {e}")
        return {"is_dangerous": None, "error": str(e)}


# ========== STEP 2: SCRAPE WEBSITE ==========


def scrape_website(url: str):
    """
    Mengambil informasi umum dari konten website untuk dianalisis.
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        res = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(res.text, "html.parser")

        data = {
            "title": soup.title.text if soup.title else "",
            "forms": len(soup.find_all("form")),
            "has_ssl": url.startswith("https://"),
            "suspicious_inputs": [],
        }

        sus_fields = ["pin", "password", "cvv", "nik", "atm", "ibu"]
        for inp in soup.find_all("input"):
            name = str(inp.get("name", "")).lower()
            placeholder = str(inp.get("placeholder", "")).lower()
            for word in sus_fields:
                if word in name or word in placeholder:
                    if word not in data["suspicious_inputs"]:
                         data["suspicious_inputs"].append(word)
        return data

    except Exception as e:
        logger.error(f"Scrape error: {e}")
        return {"error": str(e)}


# ========== STEP 3: WHOIS ==========


def get_domain_info(url: str):
    """
    Mengambil data WHOIS domain seperti umur domain.
    """
    try:
        from urllib.parse import urlparse

        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        age_days = None
        if created:
            age_days = (datetime.now() - created).days

        return {
            "domain": domain,
            "created_at": str(created) if created else None,
            "is_new": True if age_days and age_days < 30 else False,
            "age_days": age_days,
        }

    except Exception as e:
        logger.warning(f"WHOIS Error: {e}")
        return {"error": str(e)}


# ========== STEP 4: ANALISIS DENGAN AI (URL) ==========


def analyze_with_openai(
    url, website_data, google_data, domain_info, message_text, category
):
    """
    Analisis mendalam menggunakan GPT-4o-mini (UNTUK PESAN DENGAN URL).
    """
    try:
        prompt = f"""
Kamu adalah ahli keamanan digital Indonesia. Analisis kemungkinan penipuan dari data berikut.
Tugas utama: Tentukan apakah ini penipuan dan berikan skor risiko (0-100).

URL: {url}
Data Google Safe Browsing: {json.dumps(google_data, indent=2, ensure_ascii=False)}
Data Website (Hasil Scrape): {json.dumps(website_data, indent=2, ensure_ascii=False)}
Info Domain (WHOIS): {json.dumps(domain_info, indent=2, ensure_ascii=False)}
Pesan Lengkap dari User: {message_text}
Kategori: {category}

Aturan Analisis PENTING:
1.  Jika `website_data` mengandung "error" (terutama 'getaddrinfo failed'): Ini TANDA BAHAYA BESAR. Website 99% palsu/tidak ada. Beri skor > 85.
2.  Jika `website_data` *TIDAK* mengandung "error", TAPI `domain_info` mengandung "error": Ini berarti website AKTIF, tapi data WHOIS gagal diambil. Ini BUKAN tanda bahaya, anggap sebagai 'informasi tidak tersedia', jangan naikkan skor risiko karena ini.
3.  `is_new: true`: Sangat mencurigakan (skor +20).
4.  `suspicious_inputs` (pin, cvv, nik, ibu): Sangat berbahaya (skor +50).
5.  Pesan User: Cari kata-kata mendesak ('SEGERA', 'Batas: 24 jam') atau iming-iming ('SELAMAT!'). Jika ada, naikkan skor (+10).
6.  Kategori 'Bansos / Pemerintah': Website HARUS berakhiran .go.id. Selain itu, 99% penipuan (skor > 90).

Jawab HANYA dalam format JSON berikut:
{{
  "is_scam": true/false,
  "risk_score": <angka 0-100>,
  "status": "<safe/suspicious/dangerous>",
  "reasons": ["Alasan 1", "Alasan 2", "..."],
  "warning": "Peringatan singkat dalam bahasa Indonesia yang mudah dimengerti."
}}
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "Kamu adalah analis keamanan siber Indonesia. Jawab HANYA dalam format JSON yang valid.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=600,
        )

        result_text = response.choices[0].message.content.strip()
        result_json = json.loads(result_text)
        return result_json

    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        # Fallback jika AI gagal
        return {
            "status": "suspicious",
            "is_scam": True,
            "reasons": ["Analisis AI gagal. URL sangat mencurigakan."],
            "warning": "Gagal menganalisis URL dengan AI. Harap berhati-hati.",
            "risk_score": 60,
        }


# ========== FUNGSI AI BARU (UNTUK TEKS SAJA) ==========


def analyze_text_only_with_openai(message_text, category):
    """
    Analisis mendalam menggunakan GPT-4o-mini (UNTUK PESAN TANPA URL).
    """
    try:
        prompt = f"""
Kamu adalah ahli keamanan digital Indonesia. TIDAK ADA URL DITEMUKAN.
Tugas: Analisis HANYA TEKS pesan di bawah ini untuk tanda-tanda penipuan.

Pesan Lengkap dari User: {message_text}
Kategori: {category}

Aturan Analisis Teks:
1.  Cari iming-iming: "Selamat Anda dapat hadiah", "Menang undian", "Dapat bansos".
2.  Cari permintaan mendesak: "Telepon kami sekarang", "Segera", "Batas waktu".
3.  Cari permintaan data/tindakan: Meminta transfer, menelepon nomor tidak dikenal, memberikan data pribadi.
4.  Cari nomor telepon: Deteksi jika ada nomor telepon (seperti 08123456789).

Berdasarkan analisis ini, tentukan apakah pesan ini mencurigakan.
JANGAN beri skor risiko. Beri status 'safe' atau 'suspicious'.

Jawab HANYA dalam format JSON berikut:
{{
  "is_scam": true/false,
  "risk_score": 0,
  "status": "<safe/suspicious>",
  "reasons": ["Alasan 1", "Alasan 2", "..."],
  "warning": "Peringatan singkat dalam bahasa Indonesia yang mudah dimengerti."
}}
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "Kamu adalah analis keamanan siber Indonesia. Jawab HANYA dalam format JSON yang valid.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=400,
        )

        result_text = response.choices[0].message.content.strip()
        result_json = json.loads(result_text)
        return result_json

    except Exception as e:
        logger.error(f"AI text-only analysis error: {e}")
        return {
            "status": "error",
            "reasons": ["Gagal menganalisis pesan dengan AI.", str(e)],
            "warning": "Terjadi error saat menganalisis pesan.",
            "risk_score": 0,
        }


# ========== STEP 5: KOMBINASI ANALISIS ==========


def combine_results(url, google_data, website_data, domain_info, ai_result):
    """
    Gabungkan hasil dari semua lapisan analisis (4 lapis perlindungan)
    (Fungsi ini hanya dipanggil jika ADA URL)
    """
    reasons = []
    
    ai_reasons = ai_result.get("reasons", [])
    reasons.extend(ai_reasons[:3])

    if google_data.get("is_dangerous"):
        reasons.append("Ditemukan di blacklist Google Safe Browsing")

    if website_data.get("error"):
        reason_text = "Website tidak dapat diakses (domain mungkin palsu/tidak ada)"
        if not any("akses" in r.lower() or "resolve" in r.lower() or "gagal" in r.lower() for r in ai_reasons):
             reasons.append(reason_text)

    if website_data.get("suspicious_inputs"):
        reason_text = f"Website meminta data sensitif: {', '.join(website_data['suspicious_inputs'])}"
        if reason_text not in reasons:
            reasons.append(reason_text)

    if domain_info.get("is_new"):
        reason_text = f"Domain baru ({domain_info['age_days']} hari)"
        if reason_text not in reasons:
            reasons.append(reason_text)

    final_status = ai_result.get("status", "suspicious")
    risk_score = ai_result.get("risk_score", 50)

    if google_data.get("is_dangerous") or website_data.get("suspicious_inputs"):
        final_status = "dangerous"
        if risk_score < 80:
            risk_score = 85
            
    elif website_data.get("error") or domain_info.get("is_new"):
        if final_status == "safe":
            final_status = "suspicious"
        if risk_score < 50:
            risk_score = 55


    return {
        "status": final_status,
        "risk_score": risk_score,
        "reasons": list(dict.fromkeys(reasons))[:5],
        "warning": ai_result.get("warning", "Harap periksa alasan dengan saksama."),
    }


# ========== STEP 6: FUNGI UTAMA (DIMODIFIKASI) ==========


def check_url_for_scam(url, message_text=None, category=None):
    """
    Fungsi utama dipanggil dari views.py.
    Sekarang menangani kasus DENGAN atau TANPA URL.
    """
    
    # --- REVISI LOGIKA DIMULAI ---
    
    if url:
        # KASUS 1: URL DITEMUKAN (Alur normal 4 lapis)
        clean_url = sanitize_url(url)
        if not clean_url:
            return {"status": "error", "reasons": [f"Format URL tidak valid: {url}"]}

        google_data = check_google_safe_browsing(clean_url)
        website_data = scrape_website(clean_url)
        domain_info = get_domain_info(clean_url)

        ai_result = analyze_with_openai(
            clean_url, website_data, google_data, domain_info, message_text, category
        )

        result = combine_results(
            clean_url, google_data, website_data, domain_info, ai_result
        )
        return result
        
    else:
        # KASUS 2: TIDAK ADA URL (Alur baru: AI teks-saja)
        # Cek apakah pesannya terlalu pendek/kosong
        if not message_text or len(message_text.strip()) < 10:
             return {"status": "error", "reasons": ["Tidak ditemukan URL dalam pesan."]}
             
        # Panggil fungsi AI khusus teks
        ai_result = analyze_text_only_with_openai(message_text, category)
        
        # Format hasilnya agar konsisten
        return {
            "status": ai_result.get("status", "suspicious"),
            "risk_score": ai_result.get("risk_score", 0),
            "reasons": ai_result.get("reasons", ["Tidak ada URL, analisis teks."]),
            "warning": ai_result.get("warning", "Tidak ada URL, tapi harap tetap waspada."),
        }
    
# STEP TERAKHIR: INTEGRASI WHATSAPP (FASE 2)
import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_whatsapp(target: str, message: str) -> bool:
    """
    Kirim pesan WhatsApp via Fonnte API.
    """
    try:
        url = "https://api.fonnte.com/send"
        headers = {"Authorization": settings.FONNTE_TOKEN}
        payload = {
            "target": target,
            "message": message,
            "countryCode": "62",  # kode negara default: Indonesia
        }

        response = requests.post(url, headers=headers, data=payload, timeout=15)
        if response.status_code == 200:
            logger.info(f"[FONNTE] Pesan terkirim ke {target}")
            return True
        else:
            logger.error(f"[FONNTE] Error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        logger.error(f"[FONNTE] Exception kirim pesan: {e}")
        return False


def format_for_whatsapp(result: dict, url: str | None = None) -> str:
    """
    Format hasil analisis agar nyaman dibaca di WhatsApp.
    """
    status = result.get("status", "error")
    score = result.get("risk_score", 0)
    reasons = result.get("reasons", [])
    warning = result.get("warning", "")
    link_info = f"URL: {url}" if url else "Tidak ada URL terdeteksi."

    if status == "dangerous":
        text = f"""
🚨 *BAHAYA! PENIPUAN TERDETEKSI!*

{link_info}
*Skor Risiko:* {score}/100

*Alasan:*
"""
        for i, reason in enumerate(reasons[:5], 1):
            text += f"{i}. {reason}\n"

        text += """
⚠️ *JANGAN KLIK LINK ATAU BERIKAN DATA PRIBADI!*
☎️ Laporkan ke polisi 110 atau lembaga terkait.

Tetap waspada, lindungi data Anda 🛡️
"""
    elif status == "suspicious":
        text = f"""
⚠️ *MENCURIGAKAN*

{link_info}
*Skor Risiko:* {score}/100

*Alasan:*
"""
        for i, reason in enumerate(reasons[:5], 1):
            text += f"{i}. {reason}\n"

        text += """
💡 *Saran:*
- Jangan terburu-buru menekan tautan.
- Verifikasi sumbernya langsung dari website resmi.
"""
    elif status == "safe":
        text = f"""
✅ *AMAN - TIDAK TERDETEKSI PENIPUAN*

{link_info}
Skor Risiko: {score}/100

Tetap hati-hati ketika diminta data pribadi.
"""
    else:
        text = f"""
❌ *GAGAL MENGANALISIS PESAN*

{reasons[0] if reasons else "Terjadi kesalahan."}

Silakan kirim ulang atau ketik *help* untuk bantuan.
"""
    return text.strip()