````markdown
# Nmap Command Generator and Descriptor Tool

## Overview
This tool allows you to generate Nmap commands based on natural language prompts and understand existing Nmap commands. It supports:

- Command generation for different scan types.
- Automatic alternate commands for non-administrative users.
- AI-based analysis of scan results.
- A GUI for ease of use (Tkinter).

---

## Requirements

### Python Modules
The following Python modules are required:

- `google-genai`
- `keyring`
- `tkinter` (usually comes pre-installed with Python)
- `shlex` (standard library)
- `subprocess` (standard library)
- `json` (standard library)
- `threading` (standard library)
- `messagebox` (from tkinter)

Install the external modules using pip:

```bash
pip install google-genai keyring
````

> On Linux, if `pip` is blocked, use `pip3` or `python3 -m pip`, or use a virtual environment.

---

### Nmap Installation

#### Linux

* **Debian/Ubuntu/Kali**:

```bash
sudo apt update
sudo apt install nmap -y
```

* **Fedora/CentOS**:

```bash
sudo dnf install nmap -y
```

#### macOS

> Install [Homebrew](https://brew.sh/) first if not installed, then:

```bash
brew install nmap
```

#### Windows

> Download the official installer from [Nmap Download Page](https://nmap.org/download.html) and follow the setup instructions.

---

## Usage

1. Clone or download this repository.
2. Install Python modules as described above.
3. Make sure Nmap is installed and available in your PATH.
4. Run the GUI:

```bash
python nm.py
```

5. Enter a prompt in the generator to create an Nmap command.
6. View the generated command and description.
7. For analysis, select an existing command to understand its purpose and AI analysis of results.

---

## Troubleshooting

* **Tkinter window not resizing**: Some platforms may not support `mn.state("zoomed")`. The tool falls back to normal state automatically.
* **Permission issues with Nmap**: Some scans require administrative privileges (SYN scan, OS detection). Use `sudo` on Linux/macOS or run as Administrator on Windows.
* **Missing modules**: Ensure you install the modules with pip as described.
* **Raw socket errors**: For non-admin users, only TCP Connect (`-sT`) scans on allowed ports will work.

---

## Notes

* The tool normalizes privileged flags and `sudo` commands automatically for non-admin users.
* Only TCP connect scans (`-sT`) without privileged flags can run without elevated permissions.
* AI analysis requires a valid API key from Google AI Studio set in keyring.

---


# AI-Powered Security Scanner 

A **modern GUI-based Python security scanner** that integrates **Bandit static analysis** with **AI-powered vulnerability explanation and remediation**.
The application scans local Python projects or GitHub repositories, detects security issues using Bandit, and then uses AI to explain the vulnerability and suggest secure fixes.

The tool includes a **modern dark-mode interface built using CustomTkinter**.

---

# Features 

*  **Automated Python Security Scanning** using Bandit
*  **AI Vulnerability Analysis** using OpenAI models
*  **Detailed Explanation of Vulnerabilities**
*  **Secure Code Fix Suggestions**
*  **Modern Dark Mode GUI** using CustomTkinter
*  **Scan Local Folder or GitHub Repository**
*  **Automatic JSON Security Report Generation**
*  **Scrollable UI Output Window**

---

# Technologies Used

* Python
* Bandit (Python security linter)
* OpenAI API
* CustomTkinter
* Subprocess
* JSON
* Git

Bandit is a security tool originally developed by the **OpenStack Security Project**.

---

# Installation 

## 1. Clone the repository

```bash
git clone https://github.com/yourusername/ai-security-scanner.git
cd ai-security-scanner
```

---

## 2. Install required libraries

```bash
pip install bandit openai customtkinter
```

Make sure **git** is installed on your system.

---

# Getting an OpenAI API Key 

1. Go to https://platform.openai.com
2. Sign in or create an account
3. Navigate to **API Keys**
4. Click **Create new secret key**
5. Copy the generated key

You will enter this key inside the application when scanning.

---

# Running the Application 

Run the program:

```bash
python ai_security_scanner.py
```

The GUI interface will launch.

---

# How to Use the Scanner

1. Enter your **OpenAI API Key**
2. Choose a **Local Folder** OR enter a **GitHub repository URL**
3. Click **Start Security Scan**
4. View vulnerabilities and AI explanations in the output window
5. A **JSON report** will be generated automatically

Generated report file:

```
security_report.json
```

---

# Example Scan Output

```
Issue: Use of subprocess with shell=True
Severity: HIGH
File: app.py
Line: 10

AI Analysis:
This vulnerability occurs when shell=True is used in subprocess calls...
Attackers can inject malicious commands...

Secure Fix:
Use subprocess.run([...], shell=False)
```

---

# Project Structure

```
ai-security-scanner/
│
├── ai_security_scanner.py
├── security_report.json
├── README.md
```

---

# Future Improvements

Planned enhancements:

*  Vulnerability severity dashboard
*  Scan progress bar
*  HTML security reports
*  Color-coded vulnerabilities
*  AI automatic patch generation
*  GitHub pull request scanning
*  Packaging as a desktop application

---

# Educational Purpose

This project is designed for:

* Cybersecurity students
* Python developers
* Security researchers
* Hackathon projects
* Security automation learning

---

# License

This project is open-source and available under the **MIT License**.

---

# Author

Developed as a **Python cybersecurity automation project combining static analysis with AI assistance**.
