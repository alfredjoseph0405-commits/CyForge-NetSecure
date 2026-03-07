import subprocess
import json
import os
from datetime import datetime
from openai import OpenAI
import customtkinter as ctk
from tkinter import filedialog


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

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

app=ctk.CTk()
app.title("AI Security Scanner")
app.geometry("900x650")


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


app.mainloop()
