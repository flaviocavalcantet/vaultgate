# Working on VaultGate

## Workflow

- Work milestone by milestone from the README roadmap. Every feature gets its own branch
  from `main`, named `feature/<milestone>_<name>/<branch_name>`
  (e.g. `feature/m1_identity/token_validation`, `feature/m1_5_observability/grafana_dashboards`).
  Work outside a milestone (developer tooling, CI) uses `feature/tooling/<branch_name>`.
- One PR per branch. The owner reviews; merge with **squash** only after approval and green CI.
- Commits and PRs are authored as the repository owner. Do **not** add `Co-Authored-By`,
  `Claude-Session` or "Generated with Claude Code" lines to commit messages, PR descriptions
  or squash-merge messages (write the squash message explicitly).

## PR review loop

The **Claude review** GitHub Action (`.github/workflows/claude-review.yml`) is the only
automatic reviewer. It reviews every non-draft PR on open and on each push, posting as
`claude[bot]` with the guidelines in `.github/claude-review.md`. Do not run any other
reviewer (subagent, `/code-review`, `/security-review`) on a PR unless the owner asks:
it would duplicate the Action's review.

After opening a PR, subscribe the session to its activity so the review arrives as an
event, then:

1. Fix every 🔴 blocking finding that holds up, and the 🟡 suggestions that are cheap and
   clearly right; push.
2. Reply on each thread: what changed (with the commit), or why it stays as is.
3. Tell the owner which findings were acted on and which were declined, and why.

If the Action fails or posts nothing, report it to the owner instead of reviewing in its
place.

## Checks before pushing

- `ruff check . && ruff format --check . && pytest -q` in `api/` and `gateway/`
  (API database tests need `VAULTGATE_TEST_DATABASE_URL`, see README).
- `test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...` in `scanner/`.
- `terraform fmt -check -recursive infra/terraform` and `terraform validate` in
  `infra/terraform/envs/local` when Terraform changes; `helm lint deploy/helm/vaultgate`
  when the chart changes.
- `make obs-check` for the `observability/` configs once the observability stack is merged
  (needs Docker).
