# checker/views.py

from django.shortcuts import render, redirect
from .forms import CheckMessageForm
from .models import ScanHistory
from .services import check_url_for_scam, extract_url_from_message
import random  # <-- TAMBAHAN


def home(request):
    """Halaman utama: form pengecekan pesan"""
    
    # --- TAMBAHAN: LOGIKA MATEMATIKA ---
    # Buat pertanyaan matematika baru setiap kali halaman home di-load
    num1 = random.randint(1, 9)
    num2 = random.randint(1, 9)
    # Simpan jawaban yang benar di session, bukan di template
    request.session['math_answer'] = num1 + num2
    # --- AKHIR TAMBAHAN ---
    
    form = CheckMessageForm()
    
    # Kirim angka ke template untuk ditampilkan
    context = {
        "form": form,
        "num1": num1,
        "num2": num2
    }
    return render(request, "home.html", context)


def check_view(request):
    """Menangani submit form pengecekan dari user dengan rate limit sederhana."""
    url = None  # Inisialisasi URL

    if request.method == "POST":
        # === RATE LIMIT SESSION (maks 1x per 10 detik) ===
        import time
        ip = get_client_ip(request) or "unknown"
        now = time.time()
        cooldown = 10  # jeda minimal 10 detik

        last_check_time = request.session.get("last_check_time")
        if last_check_time and now - last_check_time < cooldown:
            wait = cooldown - (now - last_check_time)
            # langsung render halaman error bawaan untuk rate-limit
            return render(
                request,
                "error.html",
                {
                    "error_title": "Terlalu Sering Mengecek 🚦",
                    "error_message": (
                        f"Tunggu {wait:.1f} detik sebelum melakukan pengecekan lagi."
                    ),
                },
            )
        # catat waktu pengecekan terakhir di session
        request.session["last_check_time"] = now
        # === AKHIR RATE LIMIT ===

        form = CheckMessageForm(request.POST)

        if form.is_valid():
            # --- VALIDASI 1: LOGIKA HONEYPOT ---
            if form.cleaned_data.get("verification_email"):
                return redirect("home")  # Bot terdeteksi, abaikan submit

            # --- VALIDASI 2: LOGIKA MATEMATIKA ---
            expected_answer = request.session.get("math_answer")
            user_answer = form.cleaned_data.get("math_check")

            if str(user_answer) != str(expected_answer):
                form.add_error(
                    "math_check",
                    "Jawaban verifikasi salah. Silakan coba lagi.",
                )
            else:
                # --- SEMUA VALIDASI LOLOS ---
                request.session.pop("math_answer", None)

                message = form.cleaned_data["message"]
                category = form.cleaned_data.get("category", "")
                url = extract_url_from_message(message)

                result = check_url_for_scam(url, message, category)

                if result.get("status") != "error":
                    ScanHistory.objects.create(
                        url=url or "",
                        mode="web",
                        message_content=message,
                        result_status=result.get("status", "error"),
                        risk_score=result.get("risk_score", 0),
                        sender_ip=get_client_ip(request),
                    )

                return render(
                    request,
                    "result.html",
                    {"result": result, "url": url, "category": category},
                )

        # --- FORM INVALID / MATH CHECK SALAH ---
        num1 = random.randint(1, 9)
        num2 = random.randint(1, 9)
        request.session["math_answer"] = num1 + num2

        context = {"form": form, "num1": num1, "num2": num2}
        return render(request, "home.html", context)

    else:
        # Jika method GET, redirect ke 'home' yang sudah punya logika matematika
        return redirect("home")


# checker/views.py - Dasbor Statistik Penipuan Real‑Time
from django.shortcuts import render, redirect
from .models import ScanHistory
from django.db.models import Count
from django.db.models.functions import TruncDate


def history_view(request):
    """Menampilkan riwayat & dasbor statistik penipuan."""
    history_data = ScanHistory.objects.all().order_by('-checked_at')[:10]

    # === Bagian Statistik Umum ===
    total_checks = ScanHistory.objects.count()
    total_dangerous = ScanHistory.objects.filter(result_status="dangerous").count()
    total_suspicious = ScanHistory.objects.filter(result_status="suspicious").count()
    total_detected = total_dangerous + total_suspicious
    fraud_percentage = round((total_detected / total_checks * 100), 2) if total_checks else 0

    estimated_saved = int(total_detected * 0.95)

    # === Statistik per Hari (7 hari terakhir) ===
    trend_data = (
        ScanHistory.objects.filter(result_status="dangerous")
        .annotate(day=TruncDate("checked_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    trend_labels = [t["day"].strftime("%d/%m") for t in trend_data]
    trend_values = [t["count"] for t in trend_data]

    # === Statistik kategori (dari kolom category) ===
    category_data = (
        ScanHistory.objects.filter(category__isnull=False)
        .exclude(category="")
        .values("category")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    category_labels = [c["category"].title() for c in category_data]
    category_values = [c["count"] for c in category_data]

    # === 10 situs penipuan paling sering dilaporkan ===
    top_sites = (
        ScanHistory.objects.filter(result_status__in=["dangerous", "suspicious"])
        .values("url")
        .annotate(count=Count("url"))
        .order_by("-count")[:10]
    )

    context = {
        "history": history_data,
        # Statistik hero
        "total_checks": total_checks,
        "total_detected": total_detected,
        "fraud_percentage": fraud_percentage,
        "estimated_saved": estimated_saved,
        # Grafik
        "trend_labels": trend_labels,
        "trend_values": trend_values,
        "category_labels": category_labels,
        "category_values": category_values,
        # Situs top
        "top_sites": top_sites,
    }

    return render(request, "history.html", context)


def education_view(request):
    """
    Halaman Edukasi:
    berisi tips anti-penipuan digital dan tautan sumber resmi.
    """
    tips = [
        {
            "icon": "fas fa-link-slash",
            "title": "Kenali Ciri Link Palsu",
            "content": "Periksa selalu domain resmi (.go.id untuk pemerintah, .co.id atau .com untuk perusahaan legal). Waspada domain gratisan atau typo (misal: klilbca.com).",
        },
        {
            "icon": "fas fa-shield-halved",
            "title": "Jangan Beri Data Pribadi",
            "content": "PIN, OTP, CVV (3 angka di belakang kartu), dan nama ibu kandung adalah data rahsIA. Lembaga resmi TIDAK AKAN pernah memintanya via chat atau SMS.",
        },
        {
            "icon": "fas fa-magnifying-glass",
            "title": "Cek Ulang Informasi",
            "content": "Jika mendapat info (bansos, hadiah), jangan langsung percaya. Bandingkan info dengan website resmi instansi atau hubungi call center resmi mereka.",
        },
        {
            "icon": "fas fa-comments-dollar",
            "title": "Waspada Iming-Iming",
            "content": "Penipuan sering memakai taktik 'urgensi' (Segera! 24 jam lagi hangus!) atau 'iming-iming' (Selamat! Anda menang Rp 100 Juta!). Tetap tenang dan curiga.",
        },
    ]
    return render(request, "education.html", {"tips": tips})


def get_client_ip(request):
    """Helper mengambil IP pengguna untuk disimpan di ScanHistory."""
    x_forwarded_for = request.META.get("HTTP_X_FORDWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR", None)

def about_view(request):
    """Menampilkan halaman Tentang Kami (statik)."""
    return render(request, "about.html")


# FASE 2: INTEGRASI WHATSAPP BOT (REVISED)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import logging
from .services import send_whatsapp, format_for_whatsapp, extract_url_from_message, check_url_for_scam
from .models import ScanHistory
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)


@csrf_exempt
def whatsapp_webhook(request):
    """
    Endpoint yang dipanggil otomatis oleh Fonnte ketika ada pesan WA masuk.
    Tidak butuh authentikasi karena dikontrol lewat TOKEN di Fonnte Dashboard.
    ✅ Revisi:
    - Menambahkan anti-duplikasi pesan (cek 1 menit terakhir)
    - Menjalankan analisis berat di background thread (non-blocking)
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
        sender = data.get("sender")
        message = (data.get("message") or "").strip()

        if not sender:
            return JsonResponse({"error": "No sender"}, status=400)

        # --- Command Handling ---
        lower = message.lower()
        if not message:
            send_whatsapp(sender, "Halo! Kirim pesan yang ingin dicek ya 😊")
            return JsonResponse({"status": "ok"})

        if lower == "help":
            help_text = (
                "🛡️ *CekAman WhatsApp Bot*\n\n"
                "Cara pakai:\n"
                "1️⃣ Kirim pesan mencurigakan ke sini (tidak perlu pisahkan link).\n"
                "2️⃣ Tunggu 5‑10 detik, bot akan kirim hasil analisis.\n\n"
                "Ketik *test* untuk uji bot."
            )
            send_whatsapp(sender, help_text)
            return JsonResponse({"status": "ok"})

        if lower == "test":
            send_whatsapp(
                sender,
                "✅ Bot aktif dan siap melindungi Anda dari penipuan digital! 🛡️"
            )
            return JsonResponse({"status": "ok"})

        # --- Cegah pengulangan pesan (duplikasi) ---
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        recent_same = ScanHistory.objects.filter(
            sender_phone=sender,
            message_content=message,
            checked_at__gte=one_minute_ago
        ).exists()

        if recent_same:
            logger.warning(f"[FONNTE] Pesan duplikat dari {sender}, diabaikan.")
            return JsonResponse({"status": "duplicate_ignored"})

        # ===== Jalankan proses berat di thread terpisah =====
        def process_analysis(sender, message):
            try:
                url = extract_url_from_message(message)
                category = None
                result = check_url_for_scam(url, message, category=category)

                ScanHistory.objects.create(
                    url=url or "",
                    mode="whatsapp",
                    message_content=message,
                    result_status=result.get("status", "error"),
                    risk_score=result.get("risk_score", 0),
                    sender_phone=sender,
                    category=category,
                )

                reply = format_for_whatsapp(result, url)
                send_whatsapp(sender, reply)

                logger.info(f"[FONNTE] Analisis & balasan selesai untuk {sender}")

            except Exception as e:
                logger.error(f"[WHATSAPP_WEBHOOK_THREAD] Exception: {e}")

        # Jalankan thread tanpa blocking respons webhook
        worker = threading.Thread(
            target=process_analysis, args=(sender, message), daemon=True
        )
        worker.start()

        # Return OK segera ke Fonnte agar tidak retry
        return JsonResponse({"status": "processing"}, status=200)

    except Exception as e:
        logger.error(f"[WHATSAPP_WEBHOOK] Exception: {e}")
        return JsonResponse({"error": str(e)}, status=500)
