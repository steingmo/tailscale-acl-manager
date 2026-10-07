import Foundation

// MARK: - Running git and gh

struct GitError: LocalizedError {
    var message: String
    var errorDescription: String? { message }
}

/// Runs git and gh. Apps started from Finder get a minimal PATH, so tools
/// are looked up in the usual install folders.
enum GitTool {
    static func path(_ name: String) -> String? {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].map { "\($0)/\(name)" }
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Output on success; throws with git's own message otherwise.
    @discardableResult
    static func run(_ tool: String, _ args: [String], in dir: URL) async throws -> String {
        guard let exe = path(tool) else {
            throw GitError(message: tool == "gh"
                           ? "The GitHub CLI (gh) isn't installed — install it with `brew install gh` and run `gh auth login`."
                           : "\(tool) isn't installed.")
        }
        return try await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: exe)
            p.arguments = args
            p.currentDirectoryURL = dir
            var env = ProcessInfo.processInfo.environment
            env["GIT_TERMINAL_PROMPT"] = "0"   // fail instead of waiting for a password prompt
            env["GH_PROMPT_DISABLED"] = "1"
            env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
            p.environment = env
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            try p.run()
            let output = out.fileHandleForReading.readDataToEndOfFile()
            let errors = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let text = String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard p.terminationStatus == 0 else {
                let detail = String(decoding: errors, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                throw GitError(message: detail.isEmpty ? "\(tool) \(args.first ?? "") failed." : detail)
            }
            return text
        }.value
    }
}

// MARK: - Repository

/// A local clone whose policy file a GitOps workspace is linked to.
struct GitRepo {
    var root: URL

    /// The repository containing `file` (or folder), if any.
    static func containing(_ url: URL) async -> GitRepo? {
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
        let dir = exists && isDir.boolValue ? url : url.deletingLastPathComponent()
        guard let top = try? await GitTool.run("git", ["rev-parse", "--show-toplevel"], in: dir), !top.isEmpty else { return nil }
        return GitRepo(root: URL(fileURLWithPath: top))
    }

    @discardableResult
    func git(_ args: String...) async throws -> String { try await GitTool.run("git", args, in: root) }

    /// "main", from origin's HEAD; "main" when it can't be told.
    func defaultBranch() async -> String {
        guard let ref = try? await git("symbolic-ref", "--short", "refs/remotes/origin/HEAD") else { return "main" }
        return ref.hasPrefix("origin/") ? String(ref.dropFirst(7)) : ref
    }

    /// owner/name of the GitHub repository behind "origin".
    func gitHubRepo() async -> String? {
        guard let url = try? await git("remote", "get-url", "origin") else { return nil }
        return Self.gitHubRepo(fromRemote: url)
    }

    static func gitHubRepo(fromRemote url: String) -> String? {
        // git@github.com:owner/name.git, https://github.com/owner/name(.git), ssh://git@github.com/owner/name
        guard let range = url.range(of: "github.com[:/]", options: .regularExpression) else { return nil }
        var path = String(url[range.upperBound...])
        if path.hasSuffix(".git") { path.removeLast(4) }
        let parts = path.split(separator: "/")
        return parts.count == 2 ? path : nil
    }

    /// `file`'s path inside the repository.
    func relativePath(_ file: URL) -> String {
        let base = root.standardizedFileURL.resolvingSymlinksInPath().path
        let full = file.standardizedFileURL.resolvingSymlinksInPath().path
        return full.hasPrefix(base + "/") ? String(full.dropFirst(base.count + 1)) : file.lastPathComponent
    }

    /// The file as it is on GitHub's default branch (after a fetch), or nil.
    func fileOnDefaultBranch(_ path: String) async -> String? {
        let base = await defaultBranch()
        _ = try? await git("fetch", "--quiet", "origin", base)
        return try? await GitTool.run("git", ["show", "origin/\(base):\(path)"], in: root)
    }

    /// Commit `files` (path in repo → contents) on a new branch made from the
    /// default branch, and push it. Works in a temporary worktree, so the
    /// user's own checkout and branch are left alone. Returns (branch, base).
    func pushBranch(files: [String: String], title: String) async throws -> (branch: String, base: String) {
        let base = await defaultBranch()
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        stamp.locale = Locale(identifier: "en_US_POSIX")
        let branch = "policy/\(stamp.string(from: Date()))"
        let tree = FileManager.default.temporaryDirectory.appendingPathComponent("tailscale-acl-\(UUID().uuidString)")

        try await git("fetch", "--quiet", "origin", base)
        try await git("worktree", "add", "--quiet", "-b", branch, tree.path, "origin/\(base)")
        do {
            for (path, contents) in files {
                let url = tree.appendingPathComponent(path)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try contents.write(to: url, atomically: true, encoding: .utf8)
            }
            try await GitTool.run("git", ["add", "--"] + Array(files.keys), in: tree)
            let staged = try await GitTool.run("git", ["diff", "--cached", "--name-only"], in: tree)
            guard !staged.isEmpty else {
                throw GitError(message: "Nothing to propose: this is already what \(base) has on GitHub.")
            }
            try await GitTool.run("git", ["commit", "--quiet", "-m", title, "-m", "Opened with the Tailscale ACL app."], in: tree)
            try await GitTool.run("git", ["push", "--quiet", "-u", "origin", branch], in: tree)
        } catch {
            await removeWorktree(tree, branch: branch)
            throw error
        }
        await removeWorktree(tree, branch: branch)
        return (branch, base)
    }

    private func removeWorktree(_ tree: URL, branch: String) async {
        _ = try? await git("worktree", "remove", "--force", tree.path)
        _ = try? await git("branch", "-D", branch)
    }

    /// Push the change as a branch and open a pull request with `body` as its
    /// description. Returns the pull request's address — or GitHub's page for
    /// creating one, when the GitHub CLI isn't installed.
    func openPullRequest(files: [String: String], title: String, body: String) async throws -> URL {
        guard let repo = await gitHubRepo() else {
            throw GitError(message: "This repository's origin isn't on GitHub.")
        }
        let (branch, base) = try await pushBranch(files: files, title: title)
        guard GitTool.path("gh") != nil else {
            var c = URLComponents(string: "https://github.com/\(repo)/compare/\(base)...\(branch)")!
            c.queryItems = [URLQueryItem(name: "expand", value: "1"), URLQueryItem(name: "title", value: title)]
            return c.url!
        }
        let bodyFile = FileManager.default.temporaryDirectory.appendingPathComponent("pr-body-\(UUID().uuidString).md")
        try body.write(to: bodyFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: bodyFile) }
        let out = try await GitTool.run("gh", ["pr", "create", "--repo", repo, "--base", base, "--head", branch,
                                               "--title", title, "--body-file", bodyFile.path], in: root)
        guard let url = out.split(separator: "\n").last.flatMap({ URL(string: String($0)) }) else {
            throw GitError(message: "gh didn't return the pull request's address: \(out)")
        }
        return url
    }
}

// MARK: - Setup files

/// Tailscale's GitOps workflow: test the policy on pull requests, apply it
/// on merge to the default branch. Uses a federated identity (no stored secret).
func gitOpsWorkflow(policyFile: String, branch: String) -> String {
    let withPolicy = policyFile == "policy.hujson" ? "" : "\n          policy-file: \(policyFile)"
    return """
    name: Sync Tailscale ACLs

    on:
      push:
        branches: [ "\(branch)" ]
      pull_request:
        branches: [ "\(branch)" ]

    jobs:
      acls:
        permissions:
          contents: read
          id-token: write # lets the Tailscale action request a JWT from GitHub
        runs-on: ubuntu-latest

        steps:
          - uses: actions/checkout@v6

          - name: Fetch version-cache.json
            uses: actions/cache@v5
            with:
              path: ./version-cache.json
              key: version-cache.json-${{ github.run_id }}
              restore-keys: |
                version-cache.json-

          - name: Deploy ACL
            if: github.event_name == 'push'
            uses: tailscale/gitops-acl-action@v1
            with:
              oauth-client-id: ${{ secrets.TS_OAUTH_ID }}
              audience: ${{ secrets.TS_AUDIENCE }}
              tailnet: ${{ secrets.TS_TAILNET }}
              action: apply\(withPolicy)

          - name: Test ACL
            if: github.event_name == 'pull_request'
            uses: tailscale/gitops-acl-action@v1
            with:
              oauth-client-id: ${{ secrets.TS_OAUTH_ID }}
              audience: ${{ secrets.TS_AUDIENCE }}
              tailnet: ${{ secrets.TS_TAILNET }}
              action: test\(withPolicy)

    """
}
