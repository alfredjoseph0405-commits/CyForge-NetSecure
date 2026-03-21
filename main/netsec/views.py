from django.shortcuts import render,redirect
from dotenv import get_key, load_dotenv, set_key
from django.conf import settings
from .forms import keyfrm, ipfrm
from django.http import HttpResponseNotAllowed
from threading import Thread
from .tools.nmap.nscan import run_scan
def keygen(request):
    gkey=get_key(str(settings.BASE_DIR/".env"), "genai")
    if gkey==None:
        frm=keyfrm()
        return render(request, "netsec/keyform.html", {"form":frm})
    else:
        return redirect("home")
def home_view(request):
    return render(request, "netsec/home.html")
def key_set(request):
    if (request.method=="POST"):
        fr=keyfrm(request.POST)
        if fr.is_valid():
            ky=fr.cleaned_data["ky"]
            set_key(str(settings.BASE_DIR/".env"), "genai" , ky)
            load_dotenv(str(settings.BASE_DIR/".env"),override=True)
            return redirect("home")
    else:
        return HttpResponseNotAllowed(["POST"])


def thread_target(ip, container):
    result = run_scan(ip)
    container.update(result)

def view_ipask(request):
    frm=ipfrm()
    return render(request, "netsec/nmipfrm.html", {"form":frm})

def nmap_view(request):
    if request.method == "POST":
        frm=ipfrm(request.POST)
        if frm.is_valid():
            ip=frm.cleaned_data["ipaddr"]
            result = {}
            t = Thread(target=thread_target, args=(ip, result))
            t.start()
            t.join()
            result["tool"]="NMAP"
            return render(request, "netsec/output.html", result)