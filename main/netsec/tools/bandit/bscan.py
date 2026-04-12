import os
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from dotenv import get_key
from django.conf import settings

try:
    from google import genai
except ImportError:
    genai = None

try:
    import bandit
    from bandit.core import manager
except ImportError:
    bandit = None
    manager = None


class BanditTool:

    SUSPICIOUS_KEYWORDS = [
        "password", "secret", "api_key", "token", "jwt",
        "eval(", "exec(", "os.system",
        "pickle.load", "yaml.load",
        "sql", "insert", "hardcoded", "encrypt"
    ]

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.tool_name = "bandit"
        self.results = {"ai": "", "tool": self.tool_name, "out": {}}

    # ---------------- API KEY ----------------
    def get_api_key(self):
        return self.api_key or get_key(str(settings.BASE_DIR / ".env"), "genai")

    # ---------------- FILE SCAN ----------------
    def scan_directory(self, directory: str = ".") -> list:
        vulnerabilities = []
        try:
            for py_file in Path(directory).rglob("*.py"):
                content = py_file.read_text(errors="ignore").lower()
                found = [k for k in self.SUSPICIOUS_KEYWORDS if k in content]
                if found:
                    vulnerabilities.append({
                        "file": str(py_file),
                        "keywords": found
                    })
        except Exception as e:
            vulnerabilities.append({"error": str(e)})
        return vulnerabilities

    # ---------------- BANDIT CORE ----------------
    def run_bandit(self, directory: str = ".") -> dict:
        try:
            result = subprocess.run(
                ["bandit", "-r", directory, "-f", "json"],
                capture_output=True,
                text=True
            )

            if result.returncode not in [0, 1]:
                return {"error": result.stderr}

            return json.loads(result.stdout)

        except FileNotFoundError:
            return {"error": "bandit not installed or not in PATH"}
        except json.JSONDecodeError:
            return {"error": "Bandit returned invalid JSON output"}
        except Exception as e:
            return {"error": str(e)}

    # ---------------- AI ----------------
    def analyze_with_ai(self, data):
        if not genai:
            return "AI unavailable"

        client = genai.Client(api_key=self.api_key)

        prompt = f"""
Analyze these vulnerabilities:
{json.dumps(data, indent=2)}

Give severity + fixes.
"""

        res = client.models.generate_content(
            model="gemini-3.1-flash-lite-preview",
            contents=prompt
        )
        return res.text

    # ---------------- MAIN ENTRY ----------------
    def execute(self, mode=None, location=None):

        self.api_key = self.get_api_key()
        if not self.api_key:
            return {"ai": "", "tool": self.tool_name, "out": {"error": "no api key"}}

        tmp_dir = None

        # IMPORTANT CHANGE:
        # We assume `location` is already a VALID server-safe path
        # (provided by Django view via MEDIA_ROOT handling)
        scan_dir = location

        # ---------------- GIT ----------------
        if mode == "github":
            tmp_dir = tempfile.mkdtemp(prefix="bandit_")
            subprocess.run(["git", "clone", location, tmp_dir], check=False)
            scan_dir = tmp_dir

        # ---------------- SCAN ----------------
        vuln = self.scan_directory(scan_dir)

        self.results["out"]["vulnerabilities"] = vuln
        self.results["out"]["bandit"] = self.run_bandit(scan_dir)

        self.results["ai"] = self.analyze_with_ai({
            "custom_scan": vuln,
            "bandit_scan": self.results["out"]["bandit"]
        })

        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return self.results