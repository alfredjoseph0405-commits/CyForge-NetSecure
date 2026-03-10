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
        print("!!AI returned invalid JSON.")
        print(res)
        return None


def cmgenerator(pm):
    dat=gencmd(pm)
    aldat=None
    if dat and not dat["isvalid"]:
        print("!!A Valid command could not be generated...... check prompt for necessary details and try again.")
        print("!!Error Description: ",dat['desc']) if dat and dat['desc'] else print("Error description not available for bad JSON response")
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
mn=tk.Tk()
mn.withdraw()
ky=keyring.get_password("nmapcmdgen","AI_API")
while not ky:
    ky=simpledialog.askstring("GET API KEY","Enter the API key after setting it up on Google AI Studio(*Required):  ")
    if not ky:
        continue
    keyring.set_password("nmapcmdgen","AI_API",ky)
client=genai.Client(api_key=ky)
mn.deiconify()
mn.update_idletasks()
mn.geometry(f"{mn.winfo_screenwidth()}x{mn.winfo_screenheight()}+0+0")

ma=tk.Label(mn, text="Nmap Command Generator and Descriptor", font=("Arial", 30)).pack()
lft=tk.Frame(mn)
lft.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
rgt=tk.Frame(mn)
lb1=tk.Label(lft, text="Nmap Command Generator", font=("Arial", 25))
lb1.pack(fill=tk.X)
lb2=tk.Label(rgt, text="Nmap Command Descriptor", font=("Arial", 25))
lb2.pack(fill=tk.X)
rgt.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
cmlet=scrolledtext.ScrolledText(lft, wrap=tk.WORD)
cmlet.pack(fill=tk.BOTH, expand=True)
cmlab=tk.Label(rgt, text="Nmap Command:", font=("Arial", 12))
cmlab.pack(fill=tk.X)
dsclet=scrolledtext.ScrolledText(rgt, wrap=tk.WORD)
dsclet.pack(fill=tk.BOTH, expand=True)
prompt=tk.Entry(lft, font=("Arial",18))
prompt.pack(fill=tk.X)
btfr=tk.Frame(lft)
btfr.pack()
gencmbt=tk.Button(btfr, text="Generate Command", command=genbtn, height=4)
gendcsbt=tk.Button(btfr, text="Describe Command", command=descbtn, height=4)
gencmbt.pack(side=tk.LEFT, fill=tk.X, expand=True)
gendcsbt.pack(side=tk.LEFT, fill=tk.X, expand=True)
tk.mainloop()
