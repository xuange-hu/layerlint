"""Rule registry.

Every rule carries ``why`` (what actually goes wrong, concretely) and ``fix``
(the minimal change). ``layerlint explain LYR503`` renders them, because a
finding you cannot argue with is a finding that will get ignored.
"""

from __future__ import annotations

from .model import Rule

GROUPS = {
    "base": "Base image and identity",
    "layers": "Layer and cache behaviour",
    "packages": "Package installation",
    "network": "Build-time network and remote execution",
    "secrets": "Secrets baked into layers",
    "filesystem": "Filesystem permissions and layout",
    "runtime": "Process and container runtime",
    "hygiene": "Metadata and reproducibility",
}


def _r(*args, **kw) -> Rule:
    return Rule(*args, **kw)


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        # ---------------------------------------------------------------- base
        _r(
            "LYR101",
            "Base image uses a floating tag (:latest or untagged)",
            "high",
            "base",
            "A tag is a mutable pointer. Whoever can push to that repository decides "
            "what your next build runs, and the tag gives you no way to notice the "
            "change: same Dockerfile, different image, six months later.",
            "Pin the digest: FROM python@sha256:<digest>. Keep the human tag in a "
            "trailing comment so it stays readable.",
            "CWE-1357",
        ),
        _r(
            "LYR102",
            "Multi-stage build has an unnamed stage",
            "low",
            "base",
            "Two FROM lines without `AS builder` make COPY --from=0 positional: "
            "inserting a stage silently re-points every later copy at the wrong "
            "filesystem. It builds fine and ships the wrong tree.",
            "Name every stage (FROM golang:1.22 AS builder) and reference it by name.",
            "CWE-1188",
        ),
        _r(
            "LYR103",
            "No USER instruction — the container runs as root",
            "high",
            "base",
            "Root in the container is one kernel escape or one mis-scoped volume away "
            "from being root-adjacent on the host, and every process you start inherits "
            "it. Most runtime attacks assume they landed as root; this is the cheapest "
            "assumption to break.",
            "Create an unprivileged user and switch to it: RUN useradd -m app && USER "
            "app. Do the chown with --chown= on COPY, not with a second layer.",
            "CWE-250",
        ),
        _r(
            "LYR104",
            "Explicit switch back to root or uid 0",
            "medium",
            "base",
            "USER root after an earlier USER app undoes the mitigation for every step "
            "that follows, including the runtime process. The Dockerfile reads safe "
            "because the earlier line is there.",
            "Move the privileged steps into a builder stage, or drop privileges again "
            "immediately after the command that needed them.",
            "CWE-250",
        ),
        _r(
            "LYR105",
            "sudo or su used inside RUN",
            "medium",
            "base",
            "sudo anywhere in a build means the layer was written thinking about "
            "privilege escalation instead of least privilege — and it usually ships "
            "the sudo binary and its config into the image too.",
            "Reorder so root-owned steps happen before USER, then drop sudo entirely.",
            "CWE-250",
        ),
        _r(
            "LYR106",
            "HEALTHCHECK missing",
            "low",
            "runtime",
            "Without a healthcheck an orchestrator can only guess whether the process "
            "is alive. A wedged application that still holds port 8080 gets no restart, "
            "and nobody is paged.",
            "Add HEALTHCHECK --interval=30s CMD curl -fsS http://localhost/health || "
            "exit 1 (or the equivalent for your stack).",
            "CWE-754",
        ),
        # ------------------------------------------------------------- packages
        _r(
            "LYR201",
            "apt-get update and install in separate RUN instructions",
            "medium",
            "packages",
            "apt-get update writes the package index into its own layer, which Docker "
            "then caches. Tomorrow's build reuses yesterday's index and installs a "
            "package version whose published CVE fixes do not exist yet in your cache — "
            "the classic stale-cache class of supply-chain bug.",
            "Combine them: RUN apt-get update && apt-get install -y pkg && rm -rf "
            "/var/lib/apt/lists/*",
            "CWE-1104",
        ),
        _r(
            "LYR202",
            "apt-get install without --no-install-recommends",
            "low",
            "packages",
            "Recommends pull in packages you never asked for: shells, daemons, "
            "scripting runtimes. Each one is extra code in the image and extra CVE "
            "surface, for functionality nothing imports.",
            "apt-get install -y --no-install-recommends <pkg>",
            "CWE-1104",
        ),
        _r(
            "LYR203",
            "Package manager cache left in the layer",
            "low",
            "packages",
            "/var/lib/apt/lists and /root/.cache/pip are dead weight measured in tens "
            "of megabytes per image. It costs every pull, every registry transfer and "
            "every cold start, for zero benefit.",
            "rm -rf /var/lib/apt/lists/* (apt), apk add --no-cache (apk), pip install "
            "--no-cache-dir (pip), dnf clean all (dnf).",
            "CWE-1104",
        ),
        _r(
            "LYR204",
            "Package installed without a pinned version",
            "medium",
            "packages",
            "pip install requests resolves at build time to whatever is newest today. "
            "The same Dockerfile builds a different image next month, so 'the build is "
            "reproducible' is false and 'which version is deployed' is unanswerable.",
            "Pin exact versions (pip install requests==2.32.3) or install from a "
            "lockfile with --require-hashes.",
            "CWE-1104",
        ),
        _r(
            "LYR205",
            "npm install instead of npm ci",
            "low",
            "packages",
            "npm install is allowed to rewrite package-lock.json, so the lockfile you "
            "committed is not necessarily the tree you shipped, and CI drifts from local "
            "development silently.",
            "Use npm ci, which fails loudly if package.json and the lockfile disagree.",
            "CWE-1104",
        ),
        _r(
            "LYR206",
            "Package manager invoked insecurely (no HTTPS / no verification)",
            "high",
            "packages",
            "Flags like --allow-untrusted, --insecure, --trusted-host yes, "
            "--disable-gpg-check switch off the only thing standing between your build "
            "and whoever is on the wire that day. Mirrors do get hijacked.",
            "Remove the flag and fix the underlying certificate or index problem.",
            "CWE-494",
        ),
        # -------------------------------------------------------------- network
        _r(
            "LYR301",
            "Remote content piped straight into a shell",
            "critical",
            "network",
            "`curl https://example.com/i.sh | bash` executes whatever that host serves "
            "at build time, as root, with full network access and whatever build secrets "
            "are mounted. If the host is compromised — or the DNS answer is — your "
            "image is the attacker's payload.",
            "Fetch to a file, verify a checksum or signature, then execute. Prefer a "
            "distribution package.",
            "CWE-494",
        ),
        _r(
            "LYR302",
            "Script downloaded and executed without verification",
            "high",
            "network",
            "Download-then-run is only better than pipe-to-shell if something verifies "
            "the bytes. Without a checksum the file can be swapped between the fetch "
            "and the execution, and the fetch itself is unauthenticated.",
            "Pin a sha256 and check it before running, or use cosign/sigstore "
            "verification where available.",
            "CWE-494",
        ),
        _r(
            "LYR303",
            "ADD used for a remote URL",
            "medium",
            "network",
            "ADD with a URL downloads at build time, never re-validates, cannot send "
            "headers, and leaves the tarball auto-extracted in the layer. It also makes "
            "cache invalidation depend on a string comparison rather than the content.",
            "Use COPY for local files and curl with an explicit checksum for remote "
            "artifacts.",
            "CWE-494",
        ),
        _r(
            "LYR304",
            "ADD of a local archive (implicit extraction)",
            "low",
            "network",
            "ADD silently unpacks local tar/zip archives, so the layer contains "
            "whatever was inside — including paths that escape the destination when "
            "the archive was built maliciously.",
            "Use COPY for predictable semantics and extract explicitly if you meant to.",
            "CWE-1188",
        ),
        _r(
            "LYR305",
            "Remote artifact fetched over cleartext http://",
            "medium",
            "network",
            "An http:// fetch can be replaced in transit by anyone who can influence "
            "routing between the builder and the origin — the build network is not "
            "a trusted network.",
            "Use https:// and verify integrity; consider a local mirror.",
            "CWE-319",
        ),
        # -------------------------------------------------------------- secrets
        _r(
            "LYR401",
            "Secret-looking name in ENV or ARG",
            "critical",
            "secrets",
            "ENV and ARG values are not ephemeral: they are stored in the image "
            "config and printed by `docker history` for ARG, and by `docker inspect` "
            "for ENV. Anyone who can pull the image can read them, forever.",
            "Pass secrets at run time (environment, mounted file, secret manager) or "
            "use BuildKit secrets: RUN --mount=type=secret,id=tok ...",
            "CWE-798",
        ),
        _r(
            "LYR402",
            "Value that looks like a credential",
            "high",
            "secrets",
            "Keys have recognisable shapes: AKIA…, ghp_…, xoxb-…, eyJ… . A literal "
            "one in an ENV/ARG line is already burned — rotating it is mandatory, not "
            "optional, because it exists in every layer of every pull.",
            "Rotate the credential first, then move it out of the Dockerfile.",
            "CWE-798",
        ),
        _r(
            "LYR403",
            "Secret file copied into the image",
            "critical",
            "secrets",
            ".env, id_rsa, *.pem, .npmrc, .git-credentials copied into a layer are "
            "recoverable from the image even if a later RUN deletes them — see LYR503, "
            "the deletion only writes a whiteout.",
            "Add them to .dockerignore and mount them at run time.",
            "CWE-538",
        ),
        _r(
            "LYR404",
            "Credential written to disk by RUN",
            "high",
            "secrets",
            "echo secret > file inside RUN puts cleartext credentials into that layer's "
            "filesystem. Even a private registry exposes it to everyone with pull "
            "access, and registries get misconfigured.",
            "Use RUN --mount=type=secret so the value never lands in a layer.",
            "CWE-522",
        ),
        _r(
            "LYR405",
            "No .dockerignore while copying the whole tree",
            "medium",
            "secrets",
            "COPY . . with no .dockerignore sends the build context — including "
            ".git with its full history, local .env files, and any artifact left in the "
            "working tree — to the daemon and then into a layer.",
            "Write a .dockerignore that denies everything and allow-lists what the "
            "build needs.",
            "CWE-538",
        ),
        # ----------------------------------------------------------- filesystem
        _r(
            "LYR501",
            "World-writable permission granted",
            "high",
            "filesystem",
            "chmod 777 means every process in the container — including anything that "
            "lands later via a dependency — can rewrite the target. It is the standard "
            "way an executable gets replaced by something else.",
            "Grant the narrowest mode that works (usually 755/750) and own the file "
            "with COPY --chown= instead.",
            "CWE-732",
        ),
        _r(
            "LYR502",
            "rm removes files written by an earlier layer",
            "high",
            "layers",
            "A whiteout entry marks the path deleted in the top layer; the bytes still "
            "sit in the layer that wrote them. `docker save`, `docker history`, or a "
            "plain copy of the lower layer hands them over — this is how 'we deleted "
            "the key before shipping' turns into a credential leak.",
            "Delete in the same RUN that created the files, or never write them "
            "(COPY --from with only what you need).",
            "CWE-459",
        ),
        _r(
            "LYR503",
            "Relative or unset WORKDIR",
            "low",
            "filesystem",
            "A relative WORKDIR composes with the previous one, so reordering "
            "instructions silently changes where files land. '/' as a working "
            "directory means an application that writes temp files writes them to the "
            "image root.",
            "Use an absolute path: WORKDIR /app.",
            "CWE-1188",
        ),
        _r(
            "LYR504",
            "COPY . . before installing dependencies",
            "low",
            "layers",
            "Copying all sources first means every source edit invalidates the "
            "dependency layer, so every build reinstalls everything: slow pipelines and, "
            "more usefully here, needless re-fetches of remote packages.",
            "Copy the manifest first, install, then copy the rest.",
            "CWE-1188",
        ),
        # -------------------------------------------------------------- runtime
        _r(
            "LYR601",
            "ENTRYPOINT/CMD in shell form",
            "medium",
            "runtime",
            "Shell form wraps your process in /bin/sh -c, so PID 1 is the shell. It "
            "does not forward SIGTERM, so `docker stop` waits for the grace period and "
            "then kills your application without a clean shutdown — corrupted state, "
            "dropped requests, slow deploys.",
            "Use exec form: ENTRYPOINT [\"/usr/bin/app\", \"--flag\"].",
            "CWE-668",
        ),
        _r(
            "LYR602",
            "Duplicate CMD or ENTRYPOINT",
            "low",
            "runtime",
            "Only the last one takes effect. The earlier lines read as configuration "
            "but are dead text, which is how a container ends up running something "
            "nobody intended.",
            "Keep exactly one CMD and one ENTRYPOINT.",
            "CWE-1188",
        ),
        _r(
            "LYR603",
            "Privileged or management port exposed",
            "medium",
            "runtime",
            "EXPOSE 22 invites an ssh daemon into the runtime threat model; ports below "
            "1024 usually imply a service that historically assumed privilege. Neither "
            "belongs in a container that should do one thing.",
            "Expose only the application port, and debug with docker exec rather than "
            "sshd.",
            "CWE-668",
        ),
        _r(
            "LYR604",
            "Command output silenced",
            "low",
            "hygiene",
            ">/dev/null 2>&1 hides failures. A step that cannot fail is a step whose "
            "success you are asserting without evidence: missing dependency, expired "
            "certificate, wrong architecture — all silent.",
            "Let failures surface, or explicitly check the exit code.",
            "CWE-390",
        ),
        _r(
            "LYR605",
            "No metadata labels",
            "low",
            "hygiene",
            "Without OCI labels there is no source revision, no owner, no licence in "
            "the image itself, so incident response starts with archaeology instead of "
            "`docker inspect`.",
            "Add org.opencontainers.image.source/revision/licences labels.",
            "CWE-1059",
        ),
        _r(
            "LYR606",
            "Too many layers in one stage",
            "low",
            "layers",
            "Every layer is metadata the registry and runtime must carry. Dozens of "
            "tiny RUN steps slow pulls and inflate reproduction cost for no isolation "
            "benefit.",
            "Combine related commands into single RUN instructions with &&.",
            "CWE-1188",
        ),
    ]
}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]


def rule_ids() -> list[str]:
    return sorted(RULES)


def by_group(group: str) -> list[Rule]:
    return [r for r in RULES.values() if r.group == group]
