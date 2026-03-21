🔐 NetSec Toolkit – Django Based Network Security Utility

A Django-based web application that integrates Nmap scanning and AI-powered security analysis for internal network assessment.

This project is designed for educational and controlled lab environments.

🚀 Features

✅ API Key Management via .env

✅ Private IP validation (blocks public & loopback targets)

✅ Nmap Version Scan (-sV)

✅ AI-based vulnerability analysis using Google GenAI

✅ Clean formatted scan output (no horizontal overflow)

✅ Threaded scan execution (non-blocking backend logic)

🧠 Tools Integrated

Nmap – Version scanning for service detection

Google GenAI (Gemini) – Security analysis of scan results

Django – Web framework

python-dotenv – Environment variable handling

📂 Project Structure
main/
│
├── netsec/
│   ├── views.py
│   ├── services/
│   │   └── nmap_runner.py
│   ├── templates/netsec/
│   ├── forms.py
│   └── urls.py
│
├── core/
│   └── settings.py
│
├── .env
└── manage.py
⚙️ Setup Instructions
1️⃣ Clone the repository
git clone <your-repo-url>
cd <project-folder>
2️⃣ Create and activate virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
3️⃣ Install dependencies
pip install django python-dotenv google-genai
4️⃣ Install Nmap and MongoDB

Download from:
https://nmap.org/download.html

Ensure nmap is added to your system PATH.

Test with:

nmap --version

Download mongodb and mongosh

5️⃣ Configure API Key

Create an API key from google AI Studion and provide it when Prompted on first Run

6️⃣ Run the server
python manage.py runserver

Visit:

http://127.0.0.1:8000/
🔎 How It Works

User submits an IP address.

Application validates:

Must be private IP

Must not be loopback

Nmap runs:

nmap -sV <target>

Raw output is captured via subprocess.

Output is sent to GenAI model for:

Vulnerability explanation

CVE context

Risk summary

Results are displayed in formatted table view.

🔐 Security Controls

Public IP scanning blocked

Loopback scanning blocked

Timeout enforced on Nmap process

Controlled subprocess execution

No raw HTML rendering from user input

⚠️ Disclaimer

This tool is intended strictly for:

Educational purposes

Local lab environments

Authorized internal testing

Do NOT use against networks or systems without explicit permission.

🛠 Future Improvements

CVE database integration

Scan history storage (DB)

Multiple scan modes (TCP SYN, UDP, full port scan)

Wireshark PCAP analysis module