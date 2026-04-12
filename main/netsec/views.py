from django.shortcuts import render,redirect
import os
import shutil
import uuid
from dotenv import get_key, load_dotenv, set_key
from django.conf import settings
from .forms import keyfrm, BanditForm
from django.http import HttpResponseNotAllowed
from threading import Thread
from .tools.nmap.nscan import run_scan
from .tools.tshark.tsscan import genmock, pckcapture
from .tools.bandit.bscan import BanditTool
from django.core.files.storage import FileSystemStorage
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
    return render(request , "netsec/tmodeget.html")

def nmap_view(request):
        result = {}
        t = Thread(target=thread_target, args=(result,))
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
        
def get_mode_view(request):
    return render(request, "netsec/getmode.html", {"form": BanditForm()})


def bandit_view(request):
    if request.method != "POST":
        return redirect("get_mode")

    form = BanditForm(request.POST, request.FILES)

    if not form.is_valid():
        return render(request, "netsec/getmode.html", {"form": form})

    fs = FileSystemStorage()

    file = form.cleaned_data.get("file")
    folder = form.cleaned_data.get("folder")
    git = form.cleaned_data.get("git")

    mode = None
    path = None

    # ---------------- FILE ----------------
    if file:
        filename = fs.save(file.name, file)
        path = fs.path(filename)
        mode = "local"

    # ---------------- FOLDER (COPY INTO MEDIA) ----------------
    elif folder:
        if not os.path.exists(folder):
            return render(request, "netsec/getmode.html", {
                "form": form,
                "error": "Folder not found on server"
            })

        target_root = os.path.join(settings.MEDIA_ROOT, f"scan_{uuid.uuid4().hex}")
        os.makedirs(target_root, exist_ok=True)

        for root, _, files in os.walk(folder):
            for f in files:
                src = os.path.join(root, f)
                rel = os.path.relpath(src, folder)
                dst = os.path.join(target_root, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)

        path = target_root
        mode = "local"

    # ---------------- GIT ----------------
    elif git:
        path = git
        mode = "github"

    else:
        return render(request, "netsec/getmode.html", {
            "form": form,
            "error": "Provide input"
        })

    tool = BanditTool(api_key=os.environ.get("GEMINI_API_KEY"))
    result = tool.execute(mode=mode, location=path)

    return render(request, "netsec/output.html", result)