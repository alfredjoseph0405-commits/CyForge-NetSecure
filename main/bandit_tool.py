import os
import sys
import json
import shutil
import subprocess
import tempfile
import argparse
from pathlib import Path

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
        self.results = {
            "ai": "",
            "tool": self.tool_name,
            "out": {}
        }

    def get_api_key(self) -> str:
        """
        Resolve API key in priority order:
          1. Already set on the instance (passed via CLI env or constructor)
          2. GEMINI_API_KEY environment variable
          3. Interactive prompt — empty input is rejected, user must provide one
        """
        if self.api_key:
            return self.api_key

        env_key = os.environ.get("GEMINI_API_KEY")
        if env_key:
            return env_key

        while True:
            key = input("Enter your Gemini API key (required): ").strip()
            if key:
                return key
            print("  [!] API key is required and cannot be empty. Please try again.")

    def prompt_location(self) -> tuple:
        print("\n=== Bandit Security Scanner ===")
        print("Where is the code you want to scan?")
        print("  1. Local folder path")
        print("  2. GitHub repository")

        choice = input("\nEnter 1 or 2: ").strip()

        if choice == "2":
            url = input("GitHub URL: ").strip()
            if not url:
                print("  [!] No URL provided — defaulting to current directory.")
                return "local", "."
            return "github", url
        else:
            path = input("Folder path (press Enter for current directory): ").strip()
            return "local", path if path else "."

    def clone_github_repo(self, url: str, branch: str = "main") -> tuple:
        tmp = tempfile.mkdtemp(prefix="bandit_github_")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", branch, url, tmp],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                result2 = subprocess.run(
                    ["git", "clone", "--depth", "1", url, tmp],
                    capture_output=True, text=True, timeout=120
                )
                if result2.returncode != 0:
                    return tmp, result2.stderr.strip()
            return tmp, ""
        except FileNotFoundError:
            return tmp, "git not found — install git to clone GitHub repos."
        except subprocess.TimeoutExpired:
            return tmp, "Git clone timed out after 120s."
        except Exception as e:
            return tmp, str(e)



    def scan_directory(self, directory: str = ".") -> list:
        vulnerabilities = []
        try:
            python_files = list(Path(directory).rglob("*.py"))
            for py_file in python_files:
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                    found = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in content.lower()]
                    if found:
                        vulnerabilities.append({
                            "file": str(py_file),
                            "type": "potential_vulnerability",
                            "keywords_found": found
                        })
                except Exception:
                    continue
        except Exception as e:
            vulnerabilities.append({"error": str(e)})
        return vulnerabilities


    def run_bandit(self, directory: str = ".") -> dict:
        if not bandit:
            return {"error": "bandit not installed — run: pip install bandit"}
        try:
            b_mgr = manager.BanditManager(
                config_file=None,
                agg_type='file',
                output_format='json',
                excluded_paths="",
                included_paths="",
                log_level='info',
                debug=False,
                ignore_nosec=False,
                verbose=False
            )
            b_mgr.discover_files([directory], recursive=True)
            b_mgr.run_tests()
            issues = b_mgr.get_issue_list()
            # Convert to dict similar to json output
            results = {
                "results": {},
                "errors": [],
                "generated_at": "",
                "metrics": b_mgr.metrics.data
            }
            for issue in issues:
                fname = issue.fname
                if fname not in results["results"]:
                    results["results"][fname] = []
                results["results"][fname].append({
                    "code": issue.code,
                    "col_offset": issue.col_offset,
                    "end_col_offset": issue.end_col_offset,
                    "filename": issue.fname,
                    "issue_confidence": issue.confidence,
                    "issue_cwe": issue.cwe,
                    "issue_severity": issue.severity,
                    "issue_text": issue.text,
                    "line_number": issue.lineno,
                    "line_range": issue.linerange,
                    "more_info": issue.more_info,
                    "test_id": issue.test_id,
                    "test_name": issue.test_name
                })
            return results
        except Exception as e:
            return {"error": str(e)}


    def analyze_with_ai(self, vulnerabilities: list) -> str:
        if not genai:
            return "AI skipped — google-genai not installed. Run: pip install google-genai"
        try:
            client = genai.Client(api_key=self.api_key)
            prompt = (
                "You are a security expert.\n"
                "Analyze these Python code vulnerabilities and provide:\n"
                "  1. Severity rating per file (HIGH / MEDIUM / LOW)\n"
                "  2. What each flagged keyword means in context\n"
                "  3. Specific fix recommendations\n\n"
                f"{json.dumps(vulnerabilities[:50], indent=2)}"
            )
            response = client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"AI analysis failed: {e}"

    def execute(
        self,
        mode: str = None,
        location: str = None,
        branch: str = "main",
        run_bandit_cli: bool = True,
    ) -> dict:
        """
        Run the full scan pipeline and return results as a plain dictionary.
        AI analysis always runs — API key is mandatory.
        """

        # Step 1: Resolve mandatory API key
        self.api_key = self.get_api_key()

        # Step 2: Resolve scan target
        if mode is None or location is None:
            mode, location = self.prompt_location()

        self.results["out"]["mode"] = mode
        self.results["out"]["source"] = location

        # Step 3: Clone if GitHub
        tmp_dir = None
        scan_dir = location

        if mode == "github":
            print(f"\nCloning {location} ...")
            tmp_dir, clone_error = self.clone_github_repo(location, branch)
            if clone_error:
                self.results["out"]["clone_error"] = clone_error
                print(f"  [!] Clone error: {clone_error}")
            scan_dir = tmp_dir

        # Step 4: Keyword scan
        print(f"\nScanning {scan_dir} ...")
        vuln_scan = self.scan_directory(scan_dir)
        self.results["out"]["vulnerabilities"] = vuln_scan
        print(f"  Found {len(vuln_scan)} suspicious file(s).")

        # Step 5: Bandit CLI scan
        if run_bandit_cli:
            print("Running Bandit ...")
            self.results["out"]["bandit_results"] = self.run_bandit(scan_dir)

        # Step 6: AI analysis — always runs (key is guaranteed)
        print("Running AI analysis ...")
        self.results["ai"] = self.analyze_with_ai(vuln_scan)

        # Step 7: Cleanup temp clone
        if tmp_dir and Path(tmp_dir).exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Always return a plain dict — never JSON string, never None
        return dict(self.results)



def parse_args():
    parser = argparse.ArgumentParser(description="Bandit AI Security Scanner")
    parser.add_argument("directory", nargs="?", default=None,
                        help="Local directory to scan.")
    parser.add_argument("--github", metavar="URL", default=None,
                        help="GitHub repository URL to clone and scan.")
    parser.add_argument("--branch", default="main",
                        help="Branch to use when cloning (default: main).")
    parser.add_argument("--no-bandit", action="store_true",
                        help="Skip the bandit CLI scan.")
    parser.add_argument("--output", default=None,
                        help="Output file path (default: bandit/results.json).")
    return parser.parse_args()


def main():
    args = parse_args()

    # API key from environment (if set); otherwise tool will prompt
    api_key = os.environ.get("GEMINI_API_KEY")
    tool = BanditTool(api_key)

    # Resolve mode/location from CLI flags
    if args.github:
        mode, location = "github", args.github
    elif args.directory:
        mode, location = "local", args.directory
    else:
        mode, location = None, None  # will be prompted inside execute()

    # Run scan — always returns a dict
    results: dict = tool.execute(
        mode=mode,
        location=location,
        branch=args.branch,
        run_bandit_cli=not args.no_bandit,
    )

    # Save to file
    output_path = Path(args.output) if args.output else Path("bandit") / "results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2))

    # Print result dict
    print("\n" + "=" * 60)
    print(json.dumps(results, indent=2))
    print(f"\nResults saved to: {output_path}")

    # Return the dict (useful when imported as a module)
    return results


if __name__ == "__main__":
    main()
