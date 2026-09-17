import os
import sys
from policy_evaluater import check_cedar_permission
from sanitizer import get_real_git_diff, sanitize_and_scan_diff
from strands import Agent
from dotenv import load_dotenv
from strands.models.gemini import GeminiModel


# Load environment variables from .env file
load_dotenv()

gemini_model = GeminiModel(
    model_id="gemini-3.5-flash-lite"  # or "gemini-2.5-pro"
)
# Initialize the Strands SDK Agent for generating PR code summaries
pr_agent = Agent(
    name="PR-Summary-Agent",
    model=gemini_model,
    system_prompt=(
        "You are a helpful security-focused code review assistant. "
        "Summarize key changes in the provided sanitized git diff using concise bullet points."
    ),
)


def run_pr_gatekeeper(
    principal: str = 'User::"developer"',
    action: str = 'Action::"merge_pull_request"',
    resource: str = 'PullRequest::"incoming_pr"',
):
    # run the pr diff and sanitizing step one by one
    print("\n[STEP 1 & 2] Fetching & Sanitizing Git Diff...")

    # Fetch git diff (main...HEAD)
    raw_diff = get_real_git_diff()
    if not raw_diff.strip():
        print("[INFO] No changes detected in PR diff. Exiting.")
        return

    # Sanitize and scan locally before cloud API transmission
    scan_results = sanitize_and_scan_diff(raw_diff)

    print(f" -> Leaks Detected: {scan_results['has_leaked_secret']}")
    print(f" -> Vulnerabilities Found: {scan_results['vulnerability_count']}")
    print(f" -> Issue Types: {scan_results['detected_issues']}")

    print("\n[STEP 3] Evaluating Security Policy via Cedar...")

    policy_context = {
        "has_leaked_secret": scan_results["has_leaked_secret"],
        "vulnerability_count": scan_results["vulnerability_count"],
    }
    # Pass exact entity targets to Cedar evaluator
    is_allowed = check_cedar_permission(policy_context)



    if not is_allowed:
        print("\n [DENY] MERGE BLOCKED BY PR GATEKEEPER!")
        print(
            f"   Reason: Detected {scan_results['vulnerability_count']} sensitive issue(s): {scan_results['detected_issues']}"
        )

    print(
        "\n✅ [ALLOW] Cedar Policy Evaluation Passed! Safe to proceed with merge."
    )



    # Invoke Strands Agent safely using REDACTED diff
    print("\n[STEP 4] Invoking Strands AI Agent for Code Summary...")
    
    prompt = f"Summarize the following pull request diff:\n\n```diff\n{scan_results['sanitized_diff']}\n```"

    try:
        summary = pr_agent(prompt)
        print("\n" + "=" * 50)
        print("📝 PR CODE SUMMARY (Strands Agent)")
        print("=" * 50)
        print(summary)
        print("=" * 50)
    except Exception as e:
        print(f"[WARNING] Could not generate AI summary: {e}")

    sys.exit(1)

if __name__ == "__main__":
    run_pr_gatekeeper()    