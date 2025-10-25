# checker/models.py

from django.db import models
from django.utils import timezone


class ScanHistory(models.Model):
    """
    Model untuk menyimpan riwayat pengecekan dari user.
    Kini dilengkapi dengan kolom category untuk statistik.
    """

    MODE_CHOICES = [
        ('web', 'Web Browser'),
        ('whatsapp', 'WhatsApp Bot'),
    ]

    STATUS_CHOICES = [
        ('safe', 'Aman'),
        ('suspicious', 'Mencurigakan'),
        ('dangerous', 'Berbahaya'),
        ('error', 'Error'),
    ]

    # === Kolom utama ===
    url = models.URLField(max_length=500, verbose_name="URL yang Dicek")
    mode = models.CharField(max_length=12, choices=MODE_CHOICES, default='web')
    message_content = models.TextField(blank=True, verbose_name="Isi Pesan Lengkap")
    result_status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='safe'
    )
    risk_score = models.IntegerField(default=0, verbose_name="Skor Risiko (0–100)")

    # === Tambahan Baru: kategori ===
    category = models.CharField(
        max_length=50, blank=True, null=True, verbose_name="Kategori Analisis"
    )

    # === Info Pengirim ===
    sender_ip = models.GenericIPAddressField(
        blank=True, null=True, verbose_name="IP Address Pengirim"
    )
    sender_phone = models.CharField(
        max_length=20, blank=True, null=True, verbose_name="Nomor WhatsApp"
    )
    sender_name = models.CharField(
        max_length=100, blank=True, null=True, verbose_name="Nama Pengirim"
    )

    # === Waktu ===
    checked_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-checked_at']
        verbose_name = "Riwayat Pengecekan"
        verbose_name_plural = "Riwayat Pengecekan"

    def __str__(self):
        return (
            f"{self.url} - {self.result_status.upper()} "
            f"({self.checked_at:%d/%m/%Y %H:%M})"
        )