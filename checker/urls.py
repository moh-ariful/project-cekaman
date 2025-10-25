from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("check/", views.check_view, name="check"),
    path("history/", views.history_view, name="history"),
    path("education/", views.education_view, name="education"),
    path("about/", views.about_view, name="about"),
    path("webhook/whatsapp/", views.whatsapp_webhook, name="whatsapp_webhook"),
]