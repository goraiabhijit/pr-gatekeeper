import os
import json
import subprocess
from pathlib import Path

# Resolve the SAM project root from this script, regardless of where it is run.
GATEKEEPER_DIR = Path(__file__).resolve().parent.parent


def get_current_branch(repo_path: str = None) -> str:
    repo_dir = repo_path if repo_path else os.getcwd()
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def get_default_branch(repo_path: str = None) -> str:
    repo_dir = repo_path if repo_path else os.getcwd()
    for branch in ["main", "master", "origin/main", "origin/master"]:
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", branch],
                cwd=repo_dir,
                capture_output=True,
                check=True,
            )
            return branch
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    return "HEAD~1"


def get_real_git_diff(target: str = None, repo_path: str = None) -> str:
    """Fetch the branch-aware diff used by the Lambda scan."""
    repo_dir = repo_path if repo_path else os.getcwd()

    try:
        current_branch = get_current_branch(repo_path=repo_dir)
        base_branch = get_default_branch(repo_path=repo_dir)
    except FileNotFoundError:
        print("[WARNING] Git executable not found. Returning an empty diff.")
        return ""

    if target is None:
        if current_branch in ["main", "master"] or current_branch == "":
            target = "HEAD~1 HEAD"
        else:
            target = f"{base_branch}...HEAD"

    target_args = target.split() if " " in target else [target]

    try:
        result = subprocess.run(
            ["git", "diff"] + target_args + ["--", ".", ":(exclude)sanitizer.py"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        if result.stdout.strip():
            return result.stdout

        print("[INFO] No changes detected in the diff.")
        return ""
    except FileNotFoundError:
        print("[WARNING] Git executable not found. Returning an empty diff.")
        return ""
    except subprocess.CalledProcessError:
        print(f"[INFO] Target '{target}' unavailable. Falling back to HEAD~1.")

    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD~1"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        result = subprocess.run(
            ["git", "diff", "HEAD~1", "HEAD", "--", ".", ":(exclude)sanitizer.py"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return result.stdout if result.stdout.strip() else ""
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        print(f"[INFO] Unable to read fallback diff: {error}")
        return ""


def run_gatekeeper_scan():
    diff = get_real_git_diff(repo_path=os.getcwd())
    if not diff.strip():
        print("ℹ️ No changes/diff detected in the current git repository.")
        return

    repo_name = os.path.basename(os.getcwd())
    event_file = os.path.join(GATEKEEPER_DIR, "events", "temp_event.json")

    # Construct event structure expected by app.py lambda_handler
    event_payload = {
        "body": json.dumps({
            "raw_diff": diff,
            "repository": {"full_name": repo_name}
        })
    }

    os.makedirs(os.path.dirname(event_file), exist_ok=True)
    with open(event_file, "w", encoding="utf-8") as f:
        json.dump(event_payload, f, indent=2)

    print(f"🚀 [PR Gatekeeper] Invoking AWS Lambda for '{repo_name}'...\n")

    # FIX: Explicitly specify UTF-8 encoding and error replacement for Windows
    process = subprocess.run(
        ["sam", "local", "invoke", "PRGatekeeperFunction", "-e", event_file],
        cwd=GATEKEEPER_DIR,
        capture_output=True,
        text=True,
        shell=True,
        encoding="utf-8",
        errors="replace"
    )

    # Print container execution logs (S3 audit & Strands logs)
    if process.stderr:
        print(process.stderr)

    # The Lambda prints the Cedar verdict and AI summary during execution.
    # Its API response only confirms completion, so no second summary is needed here.
    if process.returncode != 0:
        print(
            f"❌ SAM invocation failed with exit code {process.returncode}."
        )

if __name__ == "__main__":
    run_gatekeeper_scan()