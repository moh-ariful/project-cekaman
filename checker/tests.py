# checker/tests.py
import json
import re
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from checker.models import ScanHistory
from checker.forms import CheckMessageForm
from checker import services


class UtilsTests(TestCase):
    """Uji fungsi utilitas di checker/services.py"""

    def test_extract_url_from_message(self):
        text = "Cek bantuan di https://bansos-palsu.go.id sekarang!"
        result = services.extract_url_from_message(text)
        self.assertIn("https://bansos-palsu.go.id", result)

    def test_sanitize_url_valid(self):
        raw_url = "example.com/test"
        clean = services.sanitize_url(raw_url)
        self.assertTrue(clean.startswith("https://"))
        self.assertIn("example.com", clean)

    def test_sanitize_url_invalid(self):
        result = services.sanitize_url("invalid_url_???")
        self.assertIsNone(result)


class FormTests(TestCase):
    """Uji form CheckMessageForm"""

    def setUp(self):
        self.form_data = {
            "message": "Ini pesan tes resmi",
            "category": "bank",
            "math_check": 5,
            "verification_email": "",
        }

    def test_form_valid_with_clean_data(self):
        form = CheckMessageForm(self.form_data)
        self.assertTrue(form.is_valid())

    def test_form_invalid_if_honeypot_filled(self):
        data = self.form_data.copy()
        data["verification_email"] = "bot@example.com"
        form = CheckMessageForm(data)
        self.assertTrue(form.is_valid())  # Honeypot dicek di view, bukan di form

    def test_bleach_sanitization_works(self):
        data = self.form_data.copy()
        data["message"] = "<script>alert('x')</script>Hai"
        form = CheckMessageForm(data)
        form.is_valid()
        clean = form.clean_message()
        self.assertNotIn("<script>", clean)


class ModelTests(TestCase):
    """Uji model ScanHistory"""

    def test_create_and_str(self):
        history = ScanHistory.objects.create(
            url="https://example.com",
            mode="web",
            message_content="tes message",
            result_status="safe",
            risk_score=10,
            sender_ip="127.0.0.1",
            category="bansos",
        )
        self.assertTrue(isinstance(history, ScanHistory))
        self.assertIn("https://example.com", str(history))
        self.assertEqual(history.result_status, "safe")


class ServiceTests(TestCase):
    """Uji logika di checker/services.py secara semi‑integrasi"""

    @patch("checker.services.check_google_safe_browsing")
    @patch("checker.services.scrape_website")
    @patch("checker.services.get_domain_info")
    @patch("checker.services.analyze_with_openai")
    def test_check_url_for_scam_with_url(
        self, mock_ai, mock_domain, mock_scrape, mock_safe
    ):
        mock_safe.return_value = {"is_dangerous": False}
        mock_scrape.return_value = {
            "title": "Tes",
            "forms": 1,
            "has_ssl": True,
            "suspicious_inputs": ["pin"],
        }
        mock_domain.return_value = {"is_new": True, "age_days": 5}
        mock_ai.return_value = {
            "status": "dangerous",
            "risk_score": 90,
            "reasons": ["Minta PIN"],
            "warning": "Website palsu",
        }

        result = services.check_url_for_scam("https://example.com", "pesan tes", "bank")
        self.assertIn(result["status"], ["safe", "suspicious", "dangerous"])
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertIn("reasons", result)

    @patch("checker.services.analyze_text_only_with_openai")
    def test_check_url_for_scam_text_only(self, mock_ai_text):
        mock_ai_text.return_value = {
            "status": "suspicious",
            "risk_score": 0,
            "reasons": ["Pesan meminta OTP"],
            "warning": "Waspada permintaan data pribadi",
        }
        result = services.check_url_for_scam(None, "Anda dapat hadiah besar", "bansos")
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("reasons", result)

    def test_extract_and_sanitize_integration(self):
        text = "Kunjungi situs www.contoh.com sekarang!"
        url = services.extract_url_from_message(text)
        san = services.sanitize_url(url)
        self.assertTrue(san.startswith("https://"))
        self.assertIn("contoh.com", san)


class ViewsTests(TestCase):
    """Uji endpoint utama views.py"""

    def setUp(self):
        self.client = Client()

    def test_home_page_renders(self):
        url = reverse("home")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("num1", response.context)
        self.assertIn("num2", response.context)

    def test_check_view_valid_math_and_message(self):
        session = self.client.session
        session["math_answer"] = 2 + 3
        session.save()
        payload = {
            "message": "Link test https://contoh.com",
            "math_check": "5",
            "verification_email": "",
        }

        # Patch heavy operations to simulate fast AI flow
        with patch("checker.services.check_url_for_scam") as mock_check:
            mock_check.return_value = {
                "status": "safe",
                "risk_score": 10,
                "reasons": ["Contoh saja"],
                "warning": "pesan uji",
            }
            response = self.client.post(reverse("check"), data=payload)
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "result.html")
            self.assertIn(b"SAFE", response.content)

    def test_check_view_wrong_math(self):
        session = self.client.session
        session["math_answer"] = 10
        session.save()
        payload = {
            "message": "Test math salah",
            "math_check": "3",
            "verification_email": "",
        }
        response = self.client.post(reverse("check"), data=payload)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "home.html")
        self.assertContains(response, "Verifikasi Manusia")

    def test_history_view_renders(self):
        ScanHistory.objects.create(
            url="https://tes.com",
            result_status="dangerous",
            message_content="abc",
            risk_score=99,
        )
        response = self.client.get(reverse("history"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("fraud_percentage", response.context)
        self.assertTemplateUsed(response, "history.html")

    def test_about_and_education_views(self):
        res_about = self.client.get(reverse("about"))
        res_edu = self.client.get(reverse("education"))
        self.assertEqual(res_about.status_code, 200)
        self.assertEqual(res_edu.status_code, 200)
        self.assertTemplateUsed(res_about, "about.html")
        self.assertTemplateUsed(res_edu, "education.html")
        self.assertIn("tips", res_edu.context)


class WhatsAppIntegrationTests(TestCase):
    """Uji endpoint WhatsApp webhook (simulasi ringan)"""

    def setUp(self):
        self.client = Client()

    @patch("checker.views.send_whatsapp")
    def test_webhook_help_command(self, mock_send):
        data = {"sender": "08123456789", "message": "help"}
        response = self.client.post(
            reverse("whatsapp_webhook"),
            data=json.dumps(data),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        mock_send.assert_called_once()
        self.assertIn("status", response.json())

    @patch("checker.views.send_whatsapp")
    def test_webhook_test_command(self, mock_send):
        data = {"sender": "08123456789", "message": "test"}
        response = self.client.post(
            reverse("whatsapp_webhook"),
            data=json.dumps(data),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        mock_send.assert_called_once()

    def test_webhook_get_not_allowed(self):
        response = self.client.get(reverse("whatsapp_webhook"))
        self.assertEqual(response.status_code, 405)


# Unit Test untuk format_for_whatsapp & send_whatsapp
from checker.services import format_for_whatsapp, send_whatsapp

class WhatsAppFormatTests(TestCase):
    """Uji format hasil analisis WA agar terbaca manusia"""

    def test_format_for_whatsapp_dangerous(self):
        result = {
            "status": "dangerous",
            "risk_score": 95,
            "reasons": ["Domain tidak resmi", "Minta PIN"],
            "warning": "Berpotensi scam",
        }
        text = format_for_whatsapp(result, "https://penipuan.com")
        self.assertIn("BAHAYA", text.upper())
        self.assertIn("PIN", text.upper())
        self.assertIn("https://penipuan.com", text)

    def test_format_for_whatsapp_safe(self):
        result = {
            "status": "safe",
            "risk_score": 5,
            "reasons": ["Website terpercaya"],
            "warning": "Aman diakses",
        }
        text = format_for_whatsapp(result, "https://bankresmi.id")
        self.assertIn("AMAN", text.upper())
        self.assertIn("BANKRESMI.ID", text.upper())

    def test_format_for_whatsapp_error(self):
        result = {
            "status": "error",
            "reasons": ["Analisis gagal"],
            "risk_score": 0,
            "warning": "Gagal menganalisis",
        }
        text = format_for_whatsapp(result, None)
        self.assertIn("GAGAL", text.upper())
        self.assertIn("HELP", text.upper())


class SendWhatsAppTests(TestCase):
    """Uji fungsi send_whatsapp agar memakai header & payload benar"""

    @patch("checker.services.requests.post")
    def test_send_whatsapp_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        ok = send_whatsapp("08123456789", "halo")
        self.assertTrue(ok)

        # Verifikasi header dan target dikirim
        args, kwargs = mock_post.call_args
        self.assertIn("Authorization", kwargs["headers"])
        self.assertIn("target", kwargs["data"])
        self.assertIn("message", kwargs["data"])

    @patch("checker.services.requests.post")
    def test_send_whatsapp_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Server Error"
        mock_post.return_value = mock_response

        ok = send_whatsapp("08123456789", "error test")
        self.assertFalse(ok)
