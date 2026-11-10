# ADR 0015: Image delivery

**Status:** Accepted

## Context

Until M12 the images existed only on the machine that built them: `make k3d-up` built
them from the working tree and pushed them to a registry inside the local cluster, as
`:dev` (ADR 0009). Nothing a real cluster could pull was published, and the chart's
default tag named an image that didn't exist. The tag also said nothing about what was
running: `:dev` was whatever was built last.

## Decision

**CI publishes the images to GHCR on every merge to main, tagged with the commit, and
Argo CD gives the chart the commit it is syncing as the tag. The local registry is gone.**

- **Published on merge** (`images` in `.github/workflows/ci.yml`):
  `ghcr.io/flaviocavalcantet/vaultgate-<api|gateway|scanner>:<commit>`, the full SHA.
  `main` is pushed too and moves with each merge: it is the chart's default tag, for
  rendering and for a first look, not what a deployment should run. The job uses the
  workflow's own token, with `packages: write` for that job only.
- **The chart follows the commit, with nothing written back to git.** A commit can't
  contain its own SHA, so the tag isn't in the values. The Argo CD applications
  (`deploy/argocd`) set `image.tag` to `$ARGOCD_APP_REVISION`, the commit Argo CD
  resolved and is syncing. The manifests and the images of a deployment are therefore
  of one commit, and rolling back the revision rolls back the code with it. The
  alternatives were a bot committing the tag to main after each merge, or opening a PR
  for it: both put the pin in git, at the price of a push to main outside review or of
  a second approval per merge.
- **Unmerged code is loaded, not published.** A pull request's commit, or a working
  tree, has no image on GHCR. `scripts/k3d.sh` builds the images under the same name
  and tag Argo CD will ask for and loads them into the cluster's node
  (`k3d image import`); with the chart's `IfNotPresent` the node never pulls. So the
  cluster needs no registry, and the manifests are the same in both cases.
- **Main proves what was published.** On main the k3d job waits for `images`, builds
  nothing (`VAULTGATE_IMAGES=pull`), and the node pulls the commit's images from GHCR
  before the end-to-end and cluster checks run against them.

## Consequences

- A deployment's images are identified by commit: `kubectl get pods -o yaml` says which
  code runs, and the audit of a release starts from one SHA.
- Argo CD can sync a commit before its images are published (the jobs take a few
  minutes): the pods wait in `ImagePullBackOff` and start once the images are there. A
  commit whose build failed never starts, and the previous ReplicaSet keeps serving.
- Locally, pushing a new commit to the branch makes Argo CD ask for that commit's
  images: `make k3d-images` builds and loads them. It was already needed after a code
  change.
- The tag is a name, not a digest: whoever can write the packages can move it. Signing
  the images, attesting how they were built and pinning digests are not done here
  (TM-11 in the [threat model](../threat-model.md) stays open for them).
- Images accumulate on GHCR, three per merge. Nothing prunes them yet.
- The packages must be public for a cluster to pull them without credentials. GHCR
  creates a package private unless it inherits from the repository: the first publish
  is the moment to check. The k3d job on main pulls with the workflow's token, so it
  passes either way.
