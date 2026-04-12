from django.shortcuts import render,redirect
from dotenv import get_key, load_dotenv, set_key
from django.conf import settings
from .forms import keyfrm
from django.http import HttpResponseNotAllowed
from threading import Thread
from .tools.nmap.nscan import run_scan
from .tools.tshark.tsscan import genmock, pckcapture
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


def thread_target(container):
    result = run_scan()
    container.update(result)

def tview(request):
    return render(request , "netsec/tmodeset.html")

def nmap_view(request):
    if request.method == "POST":
        frm=ipfrm(request.POST)
        if frm.is_valid():
            result = {}
            t = Thread(target=thread_target, args=(result))
            t.start()
            t.join()
            result["tool"]="NMAP"
            return render(request, "netsec/output.html", result)

def tshrk(request):
    if request.method=="POST":
        mode=request.POST.get("mode")
        if mode=="mock":
            res=genmock()
            return render(request, "netsec/output.html", res)
        elif mode=="capt":
            res=pckcapture()
            return render(request, "netsec/output.html", res)