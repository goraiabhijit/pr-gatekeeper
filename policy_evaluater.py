import os
import multiprocessing

from cedarpy import is_authorized


POLICY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "security.cedar",
)
CEDAR_TIMEOUT_SECONDS = 5


def _evaluate_policy_worker(request: dict, policy_set: str, result_pipe) -> None:
    """Run the native Cedar call in a process that can be terminated safely."""
    try:
        response = is_authorized(request, policy_set, entities=[])
        result_pipe.send((True, response.allowed))
    except Exception as error:
        result_pipe.send((False, str(error)))
    finally:
        result_pipe.close()


def check_cedar_permission(scan_findings: dict) -> bool:
    """Evaluate the merge policy using the Cedar policy bundled with the app."""
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as policy_file:
            policy_set = policy_file.read()

        request = {
            "principal": 'User::"developer"',
            "action": 'Action::"merge_pull_request"',
            "resource": 'PullRequest::"incoming_pr"',
            "context": {
                "has_leaked_secret": scan_findings.get(
                    "has_leaked_secret", False
                ),
                "vulnerability_count": scan_findings.get(
                    "vulnerability_count", 0
                ),
            },
        }

        parent_pipe, child_pipe = multiprocessing.Pipe(duplex=False)
        evaluator = multiprocessing.Process(
            target=_evaluate_policy_worker,
            args=(request, policy_set, child_pipe),
            daemon=True,
        )
        evaluator.start()
        child_pipe.close()

        try:
            if not parent_pipe.poll(CEDAR_TIMEOUT_SECONDS):
                evaluator.terminate()
                evaluator.join(timeout=1)
                print("[ERROR] Cedar policy evaluation timed out.")
                return False

            succeeded, result = parent_pipe.recv()
            if not succeeded:
                print(f"[ERROR] Cedar policy evaluation failed: {result}")
                return False
            return result
        finally:
            if evaluator.is_alive():
                evaluator.terminate()
            evaluator.join(timeout=1)
            parent_pipe.close()
    except Exception as error:
        print(f"[ERROR] Cedar policy evaluation failed: {error}")
        return False


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



