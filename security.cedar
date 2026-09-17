forbid (
    principal,
    action == Action::"merge_pull_request",
    resource
)
when {
    context.has_leaked_secret == true || context.vulnerability_count > 0
};


permit (
    principal == User::"developer",
    action == Action::"merge_pull_request",
    resource == PullRequest::"incoming_pr"
);