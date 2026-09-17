import re
import subprocess

def get_real_git_diff(target: str = "HEAD") -> str:
    # Check if HEAD~1 exists (is it the initial commit?)
    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD~1"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        print("[INFO] This is the initial commit.")
        return ""

    
    try:
        result = subprocess.run(
            ["git", "diff", target, "--", ".", ":(exclude)sanitizer.py"],
            capture_output=True,
            text=True,
            check=True
        )
        temp=result.stdout
        if not temp.strip():
            print("[INFO] No changes detected in the diff.")
            return ""
        return result.stdout
    
    except Exception as e:
        print(f"Error reading git diff: {e}")
        return ""




def sanitize_and_scan_diff(raw_diff: str) -> dict:
        patterns = {
        "AWS_KEY": r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{16,}["\']',
        "GENERIC_SECRET": r'(?i)(api_key|secret|password|bearer_token)\s*=\s*["\'][^"\'\s]{8,}["\']',
        "COMMITTED_ENV_FILE": r'(?i)(diff --git a/.*\.env|^\+\+\+ b/.*\.env)'
    }
        sanitized_diff = raw_diff
        detected_issues = []

        for issue_type, regex in patterns.items():
            if re.search(regex, raw_diff, re.MULTILINE):
                detected_issues.append(issue_type)

# mask the secret values left to do
        secret_value_regex = r'(?i)(api_key|secret|password|bearer_token|aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\'\s]+["\']'
        sanitized_diff = re.sub(
            secret_value_regex,
            r'\1 = "<REDACTED_SECRET>"',
            sanitized_diff
    )


        has_leak = len(detected_issues) > 0        


        return {
        "has_leaked_secret": has_leak,
        "detected_issues": detected_issues,
        "sanitized_diff": sanitized_diff,
        "vulnerability_count": len(detected_issues)
    }



if __name__ == "__main__":
    real_diff = get_real_git_diff("HEAD~1")
   
    if not real_diff.strip():
       print("[INFO] No diff available to scan. Skipping security check.")

    else:
        print("Git diff found. Scanning for secrets...")
        output = sanitize_and_scan_diff(real_diff)

        print(f"Leak Detected: {output['has_leaked_secret']}")
        print(f"Issues Found: {output['detected_issues']}")
        print(f"Vulnerability Count: {output['vulnerability_count']}")
        print("\n--- SANITIZED DIFF FOR LLM ---")
        print(output["sanitized_diff"])
        

