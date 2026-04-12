import random
import time
import struct
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from google import genai
from dotenv import get_key
import subprocess
from pathlib import Path
def genmock(num_packets=10):
    # 1. PCAP Global Header (24 bytes)
    # Magic number, Version (2.4), Timezone, Sigfigs, Snaplen (65535), Network (Ethernet=1)
    pcap_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    fs=FileSystemStorage()
    fn=fs.save(settings.BASE_DIR/"cap.pcap", ContentFile(b""))
    flpath=fs.path(fn)
    with open(flpath, "wb") as f:
        f.write(pcap_header)
        for _ in range(num_packets):
            # 2. Generate random payload and packet data
            # Simplified: Ethernet(14) + IP(20) + UDP(8) = 42 bytes overhead
            payload_size = random.randint(10, 100) 
            packet_data = bytes([random.getrandbits(8) for _ in range(42 + payload_size)])
            
            # 3. Packet Header (16 bytes)
            # Timestamp (seconds), Timestamp (microseconds), Captured length, Original length
            ts_sec = int(time.time())
            ts_usec = random.randint(0, 999999)
            cap_len = len(packet_data)
            orig_len = len(packet_data)
            
            packet_header = struct.pack("<IIII", ts_sec, ts_usec, cap_len, orig_len)
            
            # 4. Write header and packet to file
            f.write(packet_header)
            f.write(packet_data)
    res={}
    path = Path("cap.pcap").resolve()
    psr=subprocess.run(["tshark", "-r", str(path), "-T", "fields" , "-e" , "ip.src", "-e" , "ip.dst", "-e" , "_ws.col.Protocol"], capture_output=True, text=True, check=False)
    out=psr.stdout or "tshark returned no output."
    res["out"]=out.strip()
    res["ai"]=genaianalz(out)
    res["tool"]="TSHARK"
    return res
def genaianalz(cont):
    client=genai.Client(api_key=get_key(str(settings.BASE_DIR/".env"), "genai"))
    ans=client.models.generate_content(
        model="gemini-3.1-flash-lite-preview",
        contents=f"""
You are a cybersecurity analyst.

Analyze the following network traffic summary and identify:
- suspicious patterns
- unusual communication
- possible vulnerabilities

Data:
{cont}
""",
    )
    return ans.candidates[0].content.parts[0].text

def pckcapture():
    fs=FileSystemStorage()
    fn=fs.save(settings.BASE_DIR/"cap.pcap", ContentFile(b""))
    filepath=fs.path(fn)
    ts = subprocess.Popen(["tshark", "-i", "eth0", "-w", filepath])
    time.sleep(1)
    try:
        subprocess.run(["nmap", "-sV", "-sC", "-T4","--max-retries", "2","victim"], timeout=80)
    finally:
        ts.terminate()
        try:
            ts.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ts.kill()
    
    path = Path(filepath).resolve()
    psr=subprocess.run(["tshark", "-r", str(path), "-T", "fields" , "-e" , "ip.src", "-e" , "ip.dst", "-e" , "_ws.col.Protocol"], capture_output=True, text=True, check=False)
    out=psr.stdout or "tshark returned no output."
    res = {}
    res["out"] = out.strip()
    res["ai"] = genaianalz(out)
    res["tool"] = "TSHARK"
    return res
    