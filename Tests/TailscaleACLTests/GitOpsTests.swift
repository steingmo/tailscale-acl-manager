import XCTest
@testable import TailscaleACL

final class GitOpsTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("gitops-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
    }

    @discardableResult
    func git(_ args: String..., in where_: URL) async throws -> String {
        try await GitTool.run("git", Array(args), in: where_)
    }

    /// origin.git (bare, stands in for GitHub) with policy.hujson on main, and
    /// a clone that the user has on their own branch with local edits.
    func makeRepos() async throws -> (clone: URL, origin: URL) {
        let origin = dir.appendingPathComponent("origin.git")
        let seed = dir.appendingPathComponent("seed")
        let clone = dir.appendingPathComponent("clone")
        try await git("init", "--quiet", "--bare", "-b", "main", origin.path, in: dir)
        try await git("init", "--quiet", "-b", "main", seed.path, in: dir)
        for repo in [seed] {
            try await git("config", "user.email", "test@example.com", in: repo)
            try await git("config", "user.name", "Test", in: repo)
            try await git("config", "commit.gpgsign", "false", in: repo)
        }
        try "{\"groups\": {}}\n".write(to: seed.appendingPathComponent("policy.hujson"), atomically: true, encoding: .utf8)
        try await git("add", "policy.hujson", in: seed)
        try await git("commit", "--quiet", "-m", "initial", in: seed)
        try await git("remote", "add", "origin", origin.path, in: seed)
        try await git("push", "--quiet", "origin", "main", in: seed)
        try await git("clone", "--quiet", origin.path, clone.path, in: dir)
        try await git("config", "user.email", "test@example.com", in: clone)
        try await git("config", "user.name", "Test", in: clone)
        try await git("config", "commit.gpgsign", "false", in: clone)
        try await git("checkout", "--quiet", "-b", "my-work", in: clone)
        try "{\"groups\": {\"group:wip\": []}}\n".write(to: clone.appendingPathComponent("policy.hujson"), atomically: true, encoding: .utf8)
        return (clone, origin)
    }

    func testPushesABranchWithoutTouchingTheUsersCheckout() async throws {
        let (clone, _) = try await makeRepos()
        let file = clone.appendingPathComponent("policy.hujson")
        let found = await GitRepo.containing(file)
        let repo = try XCTUnwrap(found)
        XCTAssertEqual(repo.root.resolvingSymlinksInPath().path, clone.path)
        XCTAssertEqual(repo.relativePath(file), "policy.hujson")
        let base = await repo.defaultBranch()
        XCTAssertEqual(base, "main")
        let onMain = await repo.fileOnDefaultBranch("policy.hujson")
        XCTAssertEqual(onMain, "{\"groups\": {}}")

        let new = "{\"groups\": {\"group:eng\": [\"amy@x.com\"]}}\n"
        let pushed = try await repo.pushBranch(files: ["policy.hujson": new, ".github/workflows/tailscale.yml": "name: x\n"],
                                               title: "Update tailnet policy")
        XCTAssertEqual(pushed.base, "main")
        XCTAssertTrue(pushed.branch.hasPrefix("policy/"))

        // On the remote, the branch has the new file; the user's checkout is untouched.
        try await git("fetch", "--quiet", "origin", in: clone)
        let remoteFile = try await git("show", "origin/\(pushed.branch):policy.hujson", in: clone)
        XCTAssertEqual(remoteFile + "\n", new)
        let workflow = try await git("show", "origin/\(pushed.branch):.github/workflows/tailscale.yml", in: clone)
        XCTAssertEqual(workflow, "name: x")
        let current = try await git("rev-parse", "--abbrev-ref", "HEAD", in: clone)
        XCTAssertEqual(current, "my-work")
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "{\"groups\": {\"group:wip\": []}}\n", "local edits kept")
        let worktrees = try await git("worktree", "list", in: clone)
        XCTAssertEqual(worktrees.split(separator: "\n").count, 1, "temporary worktree removed")
        let localBranches = try await git("branch", "--list", pushed.branch, in: clone)
        XCTAssertEqual(localBranches, "", "temporary local branch removed")
    }

    func testNothingToProposeWhenUnchanged() async throws {
        let (clone, _) = try await makeRepos()
        let found = await GitRepo.containing(clone)
        let repo = try XCTUnwrap(found)
        do {
            _ = try await repo.pushBranch(files: ["policy.hujson": "{\"groups\": {}}\n"], title: "No change")
            XCTFail("expected nothing to propose")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Nothing to propose"))
        }
        let worktrees = try await git("worktree", "list", in: clone)
        XCTAssertEqual(worktrees.split(separator: "\n").count, 1, "cleaned up after a failure too")
    }

    func testNotARepository() async {
        let plain = dir.appendingPathComponent("plain")
        try? FileManager.default.createDirectory(at: plain, withIntermediateDirectories: true)
        let none = await GitRepo.containing(plain)
        XCTAssertNil(none)
    }

    func testGitHubRemotesAndWorkflow() {
        XCTAssertEqual(GitRepo.gitHubRepo(fromRemote: "git@github.com:nema/tailnet-policy.git"), "nema/tailnet-policy")
        XCTAssertEqual(GitRepo.gitHubRepo(fromRemote: "https://github.com/nema/tailnet-policy"), "nema/tailnet-policy")
        XCTAssertEqual(GitRepo.gitHubRepo(fromRemote: "ssh://git@github.com/nema/tailnet-policy.git"), "nema/tailnet-policy")
        XCTAssertNil(GitRepo.gitHubRepo(fromRemote: "git@gitlab.com:nema/tailnet-policy.git"))

        let plain = gitOpsWorkflow(policyFile: "policy.hujson", branch: "main")
        XCTAssertTrue(plain.contains("uses: tailscale/gitops-acl-action@v1"))
        XCTAssertTrue(plain.contains("action: apply") && plain.contains("action: test"))
        XCTAssertTrue(plain.contains("branches: [ \"main\" ]"))
        XCTAssertFalse(plain.contains("policy-file:"))
        let custom = gitOpsWorkflow(policyFile: "tailscale/policy.hujson", branch: "trunk")
        XCTAssertEqual(custom.components(separatedBy: "policy-file: tailscale/policy.hujson").count - 1, 2)
        XCTAssertTrue(custom.contains("branches: [ \"trunk\" ]"))
    }
}
