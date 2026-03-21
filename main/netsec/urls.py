from django.urls import path
from . import views
urlpatterns=[
    path("",views.keygen,name="key_gen"),
    path("keyset" , views.key_set, name="key_set"),
    path("home" , views.home_view, name="home"),
    path("ipask", views.view_ipask, name="ipask"),
    path("nmap_view", views.nmap_view, name="nmap_view")
]