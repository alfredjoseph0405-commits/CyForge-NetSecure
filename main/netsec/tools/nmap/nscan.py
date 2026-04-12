from google import genai
import subprocess
from dotenv import get_key
from django.conf import settings
def nmapscn():
    ot=""
    try:
        output = subprocess.run(
            [r"nmap", "-sV", "-sC", "-T4", "--max-retries", "2", "victim"],
            capture_output=True,
            text=True,
            check=False,
            timeout=80
        )
        combined_output = (output.stdout or "") + (output.stderr or "")
        ot = combined_output.strip() or "Nmap returned no output."
    except subprocess.TimeoutExpired:
        ot = "Scan timed out."
    except Exception as e:
        ot = f"Unexpected error: {str(e)}"
    return ot
def run_scan():
    client=genai.Client(api_key=get_key(str(settings.BASE_DIR/".env"), "genai"))
    dic={}
    dic["out"]=nmapscn()
    ans=client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents="""
I am running a nmap version scan -sV and -sC and here is my output analyse and give possible vulnerabilities in this system in accordance with current CVE database
if the Nmap was not run then the user provided a non private ip and thus the scan was blocked
for other nmap originated error explain why it occurred"""+dic["out"],
    )
    dic["ai"]=ans.candidates[0].content.parts[0].text
    return dic