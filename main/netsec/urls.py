from django.urls import path
from . import views
urlpatterns=[
    path("",views.keygen,name="key_gen"),
    path("keyset" , views.key_set, name="key_set"),
    path("home" , views.home_view, name="home"),
    path("nmap", views.nmap_view, name="nmap_view"),
    path("tshark", views.tshrk, name="tshrk"),
]