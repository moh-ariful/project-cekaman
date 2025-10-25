from django.contrib import admin
from .models import ScanHistory

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    """
    Kustomisasi tampilan admin untuk model ScanHistory.
    """
    
    # Menampilkan kolom-kolom ini di halaman daftar
    list_display = (
        'url', 
        'result_status', 
        'risk_score', 
        'mode', 
        'checked_at',
        'sender_ip',
        'sender_phone',
    )
    
    # Menambahkan filter di sidebar kanan
    list_filter = (
        'result_status', 
        'mode', 
        'checked_at',
    )
    
    # Menambahkan kotak pencarian
    search_fields = (
        'url', 
        'message_content', 
        'sender_ip', 
        'sender_phone', 
        'sender_name',
    )
    
    # Mengelompokkan field di halaman edit/detail
    fieldsets = (
        ('Hasil Analisis', {
            'fields': ('result_status', 'risk_score')
        }),
        ('Informasi Pesan', {
            'fields': ('url', 'message_content')
        }),
        ('Informasi Pengirim', {
            'fields': ('mode', 'sender_ip', 'sender_phone', 'sender_name')
        }),
        ('Waktu Pengecekan', {
            'fields': ('checked_at',)
        }),
    )
    
    # Membuat beberapa field hanya bisa dibaca (read-only)
    readonly_fields = ('checked_at',)
    
    # Mengurutkan default berdasarkan tanggal pengecekan (terbaru dulu)
    ordering = ('-checked_at',)