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

## License

This tool is provided as-is for educational and internal network testing purposes. Use responsibly and only on networks you own or have permission to scan.

