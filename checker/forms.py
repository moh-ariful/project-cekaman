# checker/forms.py

from django import forms
# from captcha.fields import CaptchaField  <-- DIHAPUS
import bleach


class CheckMessageForm(forms.Form):
    message = forms.CharField(
        label="Pesan Lengkap:",
        widget=forms.Textarea(
            attrs={
                "class": (
                    "w-full bg-dark-secondary border border-dark-border rounded-lg "
                    "text-text-bright placeholder-text-gray p-3 focus:outline-none "
                    "focus:ring-2 focus:ring-red-primary"
                ),
                "placeholder": "Tempelkan seluruh pesan mencurigakan di sini...",
                "rows": 8,
            }
        ),
        max_length=5000,
    )

    category = forms.ChoiceField(
        label="Kategori (Opsional):",
        required=False,
        choices=[
            ("", "Deteksi Otomatis"),
            ("bansos", "Bansos / Pemerintah"),
            ("job", "Lowongan Kerja"),
            ("bank", "Bank / Keuangan"),
            ("shop", "Belanja Online"),
            ("other", "Lainnya"),
        ],
        widget=forms.Select(
            attrs={
                "class": (
                    "w-full bg-dark-secondary border border-dark-border rounded-lg "
                    "text-text-bright p-3 focus:outline-none focus:ring-2 "
                    "focus:ring-red-primary"
                )
            }
        ),
    )

    # --- TAMBAHAN: VERIFIKASI MATEMATIKA ---
    # Field ini untuk validasi manusia yang terlihat
    math_check = forms.IntegerField(
        label="Verifikasi Manusia:",
        required=True,
        widget=forms.NumberInput( # Menggunakan NumberInput untuk keypad mobile
            attrs={
                "class": (
                    "w-full bg-dark-secondary border border-dark-border rounded-lg "
                    "text-text-bright p-3 focus:outline-none focus:ring-2 "
                    "focus:ring-red-primary"
                ),
                "autocomplete": "off", # Mencegah browser mengisi otomatis
                "placeholder": "Ketik hasilnya di sini...",
            }
        )
    )
    # --- AKHIR TAMBAHAN ---


    # --- IMPLEMENTASI HONEYPOT ---
    # Field ini akan disembunyikan dari manusia menggunakan CSS,
    # tapi terlihat oleh bot. Jika bot mengisinya, kita tahu itu bot.
    verification_email = forms.CharField(
        label="Verifikasi Email (biarkan kosong)",
        required=False,
        widget=forms.TextInput(
             attrs={
                "class": (
                    "w-full bg-dark-secondary border border-dark-border rounded-lg "
                    "text-text-bright p-3"
                ),
                 "autocomplete": "off", # Mencegah browser mengisi otomatis
             }
        )
    )
    # --- AKHIR IMPLEMENTASI HONEYPOT ---

    def clean_message(self):
        msg = self.cleaned_data.get("message", "")
        return bleach.clean(msg)