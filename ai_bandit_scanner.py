import subprocess
import json
import os
from datetime import datetime
from openai import OpenAI

def clone_repo(repo_url):

    folder = repo_url.split("/")[-1].replace(".git","")

    if not os.path.exists(folder):

        print("\nCloning repository...\n")
        subprocess.run(["git","clone",repo_url])

    return folder


def run_bandit_scan(target):

    print("\nRunning Bandit security scan...\n")

    result = subprocess.run(
        ["python","-m","bandit","-r",target,"-f","json"],
        capture_output=True,
        text=True
    )

    if result.returncode not in [0,1]:

        print("Bandit execution failed")
        print(result.stderr)
        return []

    data = json.loads(result.stdout)
    return data.get("results",[])


def ai_analyze(issue, client):

    prompt = f"""
You are a cybersecurity expert.

Analyze this vulnerability found in Python code.

Issue: {issue['issue_text']}
Severity: {issue['issue_severity']}
File: {issue['filename']}
Line: {issue['line_number']}

Explain:
1. What the vulnerability is
2. How attackers exploit it
3. Provide a secure code fix
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role":"user","content":prompt}
        ]
    )

    return response.choices[0].message.content


def generate_report(results):

    report = {
        "scan_time": str(datetime.now()),
        "total_issues": len(results),
        "issues": results
    }

    with open("security_report.json","w") as f:
        json.dump(report,f,indent=4)

    print("\nReport saved to security_report.json\n")


def main():

    print("\nAI Powered Security Scanner\n")

    # Ask user for API key
    api_key = input("Enter your OpenAI API Key: ")

    client = OpenAI(api_key=api_key)

    print("\n1. Scan local folder")
    print("2. Scan GitHub repository")

    choice = input("\nSelect option: ")

    if choice == "2":

        repo = input("Enter GitHub repo URL: ")
        target = clone_repo(repo)

    else:

        target = input("Enter folder path: ")


    issues = run_bandit_scan(target)

    if not issues:

        print("\nNo vulnerabilities found.\n")
        return


    enriched_results = []

    for issue in issues:

        print("\n==============================")
        print("Bandit Finding")
        print("==============================")

        print("Issue:",issue["issue_text"])
        print("Severity:",issue["issue_severity"])
        print("File:",issue["filename"])
        print("Line:",issue["line_number"])

        print("\nRunning AI security analysis...\n")

        try:
            ai_result = ai_analyze(issue, client)
        except Exception as e:
            ai_result = "AI analysis failed: " + str(e)

        issue["ai_analysis"] = ai_result
        enriched_results.append(issue)

        print(ai_result)

    generate_report(enriched_results)


if __name__ == "__main__":
    main()
