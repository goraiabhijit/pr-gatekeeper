from cedarpy import is_authorized

def check_cedar_permission(scan_findings: dict) -> bool:

   # 1. Read Cedar policy file from disk
    try:
        with open("security.cedar", "r") as f:
            policy_set = f.read()
    except FileNotFoundError:
        print("[ERROR] security.cedar policy file missing!")
        return False

    # 2. Build the authorization request context matching security.cedar rules
    request = {
        "principal": 'User::"developer"',
        "action": 'Action::"merge_pull_request"',
        "resource": 'PullRequest::"incoming_pr"',
        "context": {
            "has_leaked_secret": scan_findings.get("has_leaked_secret", False),
            "vulnerability_count": scan_findings.get("vulnerability_count", 0),
        },
    }



    # 3. Perform deterministic policy evaluation locally
    response = is_authorized(request, policy_set, entities=[])

    # 4. Return the decision from Cedarpy
    return response.allowed


if __name__ == "__main__":
    print("=== TESTING CEDAR POLICY EVALUATOR ===")

    # Test Case 1: PR with leaked secrets
    vulnerable_findings = {
        "has_leaked_secret": True,
        "vulnerability_count": 1,
    }
    result_vuln = check_cedar_permission(vulnerable_findings)
    print(f"Vulnerable PR Decision -> Allowed: {result_vuln} (Expected: False)")

    # Test Case 2: Clean PR
    clean_findings = {
        "has_leaked_secret": False,
        "vulnerability_count": 0,
    }
    result_clean = check_cedar_permission(clean_findings)
    print(f"Clean PR Decision      -> Allowed: {result_clean} (Expected: True)")



