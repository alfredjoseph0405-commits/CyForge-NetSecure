from google import genai
import subprocess
from dotenv import get_key
from django.conf import settings
import ipaddress


def run_scan(ip):
    client=genai.Client(api_key=get_key(str(settings.BASE_DIR/".env"), "genai"))
    dic={}
    def valid_ip(ip):
        try:
            ipobj=ipaddress.ip_address(ip)
            return ipobj.is_private and not ipobj.is_loopback
        except ValueError:
            return False
    if valid_ip(ip):
        try:
            output = subprocess.run(
                [r"C:\Program Files (x86)\Nmap\nmap.exe", "-sV", "-Pn", "-T4", "--max-retries", "2", ip],
                capture_output=True,
                text=True,
                check=False,
                timeout=80
            )
            combined_output = (output.stdout or "") + (output.stderr or "")
            dic["out"] = combined_output.strip() or "Nmap returned no output."
        except subprocess.TimeoutExpired:
            dic["out"] = "Scan timed out."
        except Exception as e:
            dic["out"] = f"Unexpected error: {str(e)}"
    else:
        dic["out"]="Nmap was not run due to Invalid ip address"
    ans=client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents="""
I am running a nmap version scan and here is my output analyse and give possible vulnerabilities in this system in accordance with current CVE database
if the Nmap was not run then the user provided a non private ip and thus the scan was blocked
for other nmap originated error explain why it occurred"""+dic["out"],
    )
    dic["ai"]=ans.candidates[0].content.parts[0].text
    return dic