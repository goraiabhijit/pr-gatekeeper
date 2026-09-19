import re
import subprocess
import os


    # Returns the name of the currently checked-out branch.
def get_current_branch(repo_path:str = None) -> str:
    repo_dir = repo_path if repo_path else os.getcwd()
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


# Function to get the real git diff between the current branch and the target branch (default is main...HEAD)
def get_default_branch(repo_path: str = None) -> str:
    # Detects whether the primary base branch is 'main' or 'master'.
    repo_dir = repo_path if repo_path else os.getcwd()
    for branch in ["main", "master", "origin/main", "origin/master"]:
        try:
            # Check if the branch exists in the git reference log
            subprocess.run(
                ["git", "rev-parse", "--verify", branch],
                cwd=repo_dir,
                capture_output=True,
                check=True,
            )
            return branch
        except subprocess.CalledProcessError:
            continue

    # Default fallback if neither branch exists locally
    return "HEAD~1"


def get_real_git_diff(target: str = None, repo_path: str = None) -> str:
    """Fetches real git diff. Auto-detects base branch (main/master) if target is omitted."""
    repo_dir = repo_path if repo_path else os.getcwd()

    try:
        current_branch = get_current_branch(repo_path=repo_dir)
        base_branch = get_default_branch(repo_path=repo_dir)
    except FileNotFoundError:
        print("[WARNING] Git executable not found in runtime environment. Returning empty diff.")
        return ""

    if target is None:
        if current_branch in ["main", "master"] or current_branch == "":
            target = "HEAD~1 HEAD"
        else:
            target = f"{base_branch}...HEAD"

    # Split target string into command arguments if space is present (e.g. "HEAD~1 HEAD")
    target_args = target.split() if " " in target else [target]

    try:
        # Primary attempt: Compare feature branch merge-base against HEAD
        result = subprocess.run(
            ["git", "diff"] + target_args + ["--", ".", ":(exclude)sanitizer.py"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        diff_output = result.stdout

        if not diff_output.strip():
            print("[INFO] No changes detected in the diff.")
            return ""

        return diff_output

    except FileNotFoundError:
        print("[WARNING] Git executable not found in runtime environment. Returning empty diff.")
        return ""

    except subprocess.CalledProcessError:
        print(f"[INFO] Target '{target}' unavailable. Falling back to HEAD~1.")

        # Check if HEAD~1 exists (is it the initial commit?)
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD~1"],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[INFO] Initial commit or git unavailable.")
            return ""

        try:
            result = subprocess.run(
                ["git", "diff", "HEAD~1", "HEAD", "--", ".", ":(exclude)sanitizer.py"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
            )
            temp = result.stdout
            if not temp.strip():
                print("[INFO] No changes detected in the diff.")
                return ""
            return temp

        except Exception as e:
            print(f"Error reading git diff: {e}")
            return ""
    
# sanitization function -replaces secret values with <REDACTED_SECRET> and returns a dict with findings

def sanitize_and_scan_diff(raw_diff: str) -> dict:
        patterns = {
        "AWS_KEY": r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{16,}["\']',
        "GENERIC_SECRET": r'(?i)(api_key|secret|password|bearer_token)\s*=\s*["\'][^"\'\s]+["\']',
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
    real_diff = get_real_git_diff()
   
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
        

