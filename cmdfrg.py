import json
import keyring
from google import genai
import shlex
import subprocess
import tkinter as tk
from tkinter import scrolledtext
import threading
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
import os
from datetime import datetime
from openai import OpenAI
import customtkinter as ctk
from tkinter import filedialog

def permission(cm):
    res=None
    evt = threading.Event()
    def ask():
        nonlocal res
        res=messagebox.askyesno("Run Command?", f"Do you want to run this command?\n{cm}")
        evt.set()  # thread is ready

    mn.after(0, ask)  # ask in main thread
    evt.wait()        # wait for user response user responds
    return res


def normalize(cmd):
    parts = shlex.split(cmd)

    privileged_flags = {"-sS","-sU","-sN","-sF","-sX","-sA","-A","-O"}

    cln = []

    for p in parts:
        if p == "sudo":
            continue
        if p in privileged_flags:
            continue
        cln.append(p)

    if not cln or cln[0] != "nmap":
        return None  # clearly invalid command

    if "-sT" not in cln:
        cln.insert(1, "-sT")

    if "-Pn" not in cln:
        cln.insert(1, "-Pn")

    return " ".join(cln)

def gencmd(prm):
    prmpt="""
Respond ONLY in valid JSON.
{
"isvalid": true/false,
"cmd": "nmap command",
"desc": "description",
"scan_type": "scan type",
"target": "target ip",
"isadmn": true/false
}
output must strictly be in this format. 
The nmap command should be generated based on the scan type and target provided in the user input.
The description should provide a brief explanation of the scan type and what information it can reveal about the target.
If a valid command cannot be generated, set isvalid to false and provide an error description in the desc field.
if the command requires administrative privileges, set isadmn to true, otherwise set it to false.
User request:
"""
    res=client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents=prmpt+prm,
        config={"response_mime_type": "application/json"}
    )
    try:
        dat = json.loads(res.text.strip())
        return dat
    except json.JSONDecodeError:
        messagebox.showerror("Error!!","!!AI returned invalid JSON.")
        cmlet.insert(tk.END,"Error Json: \n"+res+"\n\n")
        return None


def cmgenerator(pm):
    dat=gencmd(pm)
    aldat=None
    if dat and not dat["isvalid"]:
        messagebox.showerror("ERROR!!","!!A Valid command could not be generated...... check prompt for necessary details and try again.\n\n")
        cmlet.insert(tk.END,"!!Error Description: "+dat['desc']+"\n\n") if dat and dat['desc'] else cmlet.insert(tk.END,"Error description not available for bad JSON response\n\n")
        mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
        return
    if dat==None:
        mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
        return
    mn.after(0, lambda: cmlet.insert(tk.END, "[*] - Command:  " + dat["cmd"] +f"\nScan Type: {dat['scan_type']}\nTarget: {dat['target']}\n"))
    mn.after(0, lambda: cmlab.configure(text="Nmap Command:  "+dat['cmd']))
    mn.after(0, lambda: dsclet.insert(tk.END, "[*] - Description:\n" + dat['desc'] +"\n"))
    for i in ("-sS", "-sU", "-sN", "-sF", "-sX", "-sA", "-O"):
        if i in dat["cmd"]:
            dat["isadmn"]=True
    if dat["isadmn"]:
        mn.after(0, lambda: cmlet.insert(tk.END, "[!] - This command requires administrative privileges. As safety measure such command will not be run by the script. Alternate command will be generated if posiible..\n"))
        res=client.models.generate_content(
            model="gemini-3.1-flash-lite-preview",
            contents="""
The command \""+dat["cmd"]+"\" requires administrative privileges.IS there an alternative valid  nmap command that can be run without admin privileges to achieve similar results? If yes, provide JSON of structure
also strictly dont use (-sS, -sU, -sN, -sF, -sX, -sA, -O) flags if not possible set "cmd" as "N/A"
{
"cmd": "alternate Nmap command that can be run without admin privileges" if not available then "N/A",
"desc": "description of the alternate command and how it differs from the original command if available, otherwise provide a brief explanation of why an alternate command cannot be generated"
}
""",
            config={"response_mime_type": "application/json"}
        )
        try:
            aldat = json.loads(res.text.strip())
        except json.JSONDecodeError:
            mn.after(0, lambda: cmlet.insert(tk.END, "!!! Invalid JSON for alternate command\n"))
            mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
            return
        if aldat and aldat["cmd"]=="N/A":
            mn.after(0, lambda: cmlet.insert(tk.END, "!!The original command requires administrative privileges and an alternate command is not possible to generate without admin privileges.\n"))
            mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
            return
    else:
        aldat=dat
    mn.after(0,lambda:dsclet.delete(1.0, tk.END))
    aldat["cmd"]=normalize(aldat["cmd"])
    if aldat and aldat["cmd"]!="N/A":
        mn.after(0, lambda: cmlet.insert(tk.END, "[*] - Alternate Command:  " + aldat["cmd"] + "\n"))
        mn.after(0, lambda: dsclet.insert(tk.END, "[*] - Alternate Command Description:\n" + aldat["desc"] + "\n"))
    mn.after(0, lambda: cmlab.configure(text="Nmap Command:  "+aldat["cmd"]))
    mn.after(0, lambda: dsclet.insert(tk.END, "[*] - Scan Type:  " + dat["scan_type"] + "\n"))
    mn.after(0, lambda: dsclet.insert(tk.END, "[*] - Target:  " + dat["target"] + "\n"))
    per=permission(aldat["cmd"])
    if not per:
        mn.after(0, lambda : cmlet.insert("end", "Permission denied to run the command.\n"))
        mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
        return
    cm=shlex.split(aldat["cmd"])
    if cm[0]!="nmap":
        mn.after(0, lambda: cmlet.insert(tk.END, "Skipping instance...  non-nmap command will not be executed.\n"))
        mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
        return
    out=subprocess.run(cm , capture_output=True, text=True, check=False)
    if out.returncode ==0:
        mn.after(0, lambda: cmlet.insert(tk.END, "Output:\n" + out.stdout))
        re=client.models.generate_content(
            model="gemini-3.1-flash-lite-preview",
            contents="analyse this output from nmap and what can be infered from it:  "+out.stdout
        )

        mn.after(0, lambda: dsclet.insert(tk.END, "AI Analysis:  " + re.text.strip()))
    else:
        mn.after(0, lambda: cmlet.insert(tk.END, "Output:\n" + out.stderr))
        re=client.models.generate_content(
            model="gemini-3.1-flash-lite-preview",
            contents="analyse this error from nmap that is got when i ran the command \""+dat["cmd"]+"\" and what can be infered from it:  and how to fix it"+out.stderr
        )
        mn.after(0,lambda: dsclet.insert(tk.END, "AI Analysis:  " + re.text.strip()))
    mn.after(0, lambda : gencmbt.config(state=tk.NORMAL))
    mn.after(0,lambda: cmlet.insert(tk.END, "[........] Process terminated\n\n\n"))

def command_descriptor(cm):
    res=client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents="Provide a detailed description of the following nmap command and what information it can reveal about the target:  "+cm
    )
    mn.after(0, lambda: dsclet.insert(tk.END, "AI Description:  " + res.text.strip()))
    mn.after(0, lambda: gendcsbt.config(state=tk.NORMAL))
    mn.after(0,lambda:cmlet.insert(tk.END, "[........] Process terminated\n\n\n"))

def genbtn():
    gencmbt.config(state=tk.DISABLED)
    st=prompt.get()
    if st.strip()=="":
        cmlet.insert(tk.END, "!!!Recieved empty prompt.\n")
        gencmbt.config(state=tk.NORMAL)
    else:
        cmlet.insert(tk.END, "[*] Generating command for prompt:  "+st+"\n")
        t=threading.Thread(target=cmgenerator, args=(st,), daemon=True)
        t.start()
def descbtn():
    cmlab.config(text="Nmap Command:")
    dsclet.delete(1.0, tk.END)
    gendcsbt.config(state=tk.DISABLED)
    st=prompt.get()
    if st.strip()=="":
        dsclet.insert(tk.END, "!!!Recieved empty command.\n")
        gendcsbt.config(state=tk.NORMAL)
    else:
        dsclet.insert(tk.END, "[*] Generating description for command:  "+st+"\n")
        t=threading.Thread(target=command_descriptor, args=(st,), daemon=True)
        t.start()

        
def clone_repo(repo_url):

    folder = repo_url.split("/")[-1].replace(".git","")

    if not os.path.exists(folder):
        log_box.insert("end","\nCloning repository...\n")
        subprocess.run(["git","clone",repo_url])

    return folder

def run_bandit_scan(target):

    log_box.insert("end","\nRunning Bandit scan...\n")

    result = subprocess.run(
        ["python","-m","bandit","-r",target,"-f","json"],
        capture_output=True,
        text=True
    )

    if result.returncode not in [0,1]:

        log_box.insert("end","Bandit failed\n")
        log_box.insert("end",result.stderr)
        return []

    data = json.loads(result.stdout)
    return data.get("results",[])

def ai_analyze(issue,client):

    prompt=f"""
You are a cybersecurity expert.

Issue: {issue['issue_text']}
Severity: {issue['issue_severity']}
File: {issue['filename']}
Line: {issue['line_number']}

Explain vulnerability and give secure fix.
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role":"user","content":prompt}]
    )

    return response.choices[0].message.content

def generate_report(results):

    report={
        "scan_time":str(datetime.now()),
        "total_issues":len(results),
        "issues":results
    }

    with open("security_report.json","w") as f:
        json.dump(report,f,indent=4)

    log_box.insert("end","\nReport saved: security_report.json\n")


def browse():

    folder=filedialog.askdirectory()
    folder_entry.delete(0,"end")
    folder_entry.insert(0,folder)

def start_scan():

    api_key=api_entry.get()

    if api_key=="":
        log_box.insert("end","Enter API key\n")
        return

    client=OpenAI(api_key=api_key)

    folder=folder_entry.get()
    repo=repo_entry.get()

    if repo!="":
        folder=clone_repo(repo)

    issues=run_bandit_scan(folder)

    if not issues:
        log_box.insert("end","\nNo vulnerabilities found\n")
        return

    enriched=[]

    for issue in issues:

        log_box.insert("end","\n====================\n")

        log_box.insert("end",f"Issue: {issue['issue_text']}\n")
        log_box.insert("end",f"Severity: {issue['issue_severity']}\n")
        log_box.insert("end",f"File: {issue['filename']}\n")
        log_box.insert("end",f"Line: {issue['line_number']}\n")

        log_box.insert("end","\nAI Analysis...\n")

        try:
            ai_result=ai_analyze(issue,client)
        except Exception as e:
            ai_result=str(e)

        issue["ai_analysis"]=ai_result
        enriched.append(issue)

        log_box.insert("end",ai_result+"\n")

    generate_report(enriched)





root=tk.Tk()
style = ttk.Style()
style.theme_use("clam")

bg = "#1e1e1e"
fg = "#e0e0e0"
accent = "#3a86ff"

style.configure(".", background=bg, foreground=fg)
style.configure("TFrame", background=bg)
style.configure("TLabel", background=bg, foreground=fg)
style.configure("TButton", background="#2d2d2d", foreground=fg)
style.configure("TEntry",fieldbackground="#2a2a2a",foreground="cyan",insertbackground="white")
style.map("TButton",
          background=[("active", accent)])
root.configure(bg=bg)
style.configure("TNotebook.Tab",
                background="#2d2d2d",
                foreground="#e0e0e0",
                padding=[10, 5])

style.map("TNotebook.Tab",
          background=[("selected", "#3a86ff")],
          foreground=[("selected", "#ffffff")])
root.title("CMDFRG")
root.withdraw()
ky=keyring.get_password("nmapcmdgen","AI_API")
while not ky:
    ky=simpledialog.askstring("GET API KEY","Enter the API key after setting it up on Google AI Studio(*Required):  ")
    if not ky:
        continue
    keyring.set_password("nmapcmdgen","AI_API",ky)
client=genai.Client(api_key=ky)
root.deiconify()
root.update_idletasks()
root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()-80}+0+0")


ntb=ttk.Notebook(root)
ntb.pack(fill=tk.BOTH, expand=True)
mn=ttk.Frame(ntb)
ma=ttk.Label(mn, text="Nmap Command Generator and Descriptor", font=("Arial", 30)).pack()
mfr=ttk.Frame(mn)
mfr.pack(fill=tk.BOTH, expand=True)
ntb.add(mn,text="NMAP Tool")

lft=ttk.Frame(mfr)
lft.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
rgt=ttk.Frame(mfr)
lb1=ttk.Label(lft, text="Nmap Command Generator", font=("Arial", 25))
lb1.pack(fill=tk.X)
lb2=ttk.Label(rgt, text="Nmap Command Descriptor", font=("Arial", 25))
lb2.pack(fill=tk.X)
rgt.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
cmlet=scrolledtext.ScrolledText(lft, wrap=tk.WORD,bg="#121212",fg="#00ff9c",insertbackground="white")
cmlet.pack(fill=tk.BOTH, expand=True)
cmlab=ttk.Label(rgt, text="Nmap Command:", font=("Arial", 12))
cmlab.pack(fill=tk.X)
dsclet=scrolledtext.ScrolledText(rgt, wrap=tk.WORD,bg="#121212",fg="#00ff9c",insertbackground="white")
dsclet.pack(fill=tk.BOTH, expand=True)


btfr=ttk.Frame(mn)
btfr.pack(side=tk.BOTTOM, fill=tk.BOTH)
clab=ttk.Label(btfr,font=("Arial",14), text="Enter Prompt or Command here:")
clab.pack(fill=tk.X)
prompt=ttk.Entry(btfr, font=("Arial",18))
prompt.pack(fill=tk.X)
gencmbt=ttk.Button(btfr, text="Generate Command", command=genbtn)
gendcsbt=ttk.Button(btfr, text="Describe Command", command=descbtn)
gencmbt.pack(side=tk.LEFT, fill=tk.X, expand=True)
gendcsbt.pack(side=tk.LEFT, fill=tk.X, expand=True)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app=ctk.CTkFrame(ntb)
ntb.add(app,text="Bandit")

title=ctk.CTkLabel(app,text="AI Powered Security Scanner",font=("Arial",28))
title.pack(pady=20)


api_entry=ctk.CTkEntry(app,width=500,placeholder_text="Enter OpenAI API Key")
api_entry.pack(pady=10)


folder_entry=ctk.CTkEntry(app,width=500,placeholder_text="Local Folder Path")
folder_entry.pack(pady=10)

browse_btn=ctk.CTkButton(app,text="Browse Folder",command=browse)
browse_btn.pack(pady=5)


repo_entry=ctk.CTkEntry(app,width=500,placeholder_text="GitHub Repository URL (optional)")
repo_entry.pack(pady=10)


scan_btn=ctk.CTkButton(app,text="Start Security Scan",command=start_scan)
scan_btn.pack(pady=20)


log_box=ctk.CTkTextbox(app,width=800,height=300)
log_box.pack(pady=20)

tk.mainloop()
