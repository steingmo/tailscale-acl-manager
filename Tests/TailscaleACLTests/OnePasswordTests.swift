import XCTest
@testable import TailscaleACL

/// Runs against a stand-in `op` script that logs its arguments and input.
final class OnePasswordTests: XCTestCase {
    var dir: URL!
    var log: URL { dir.appendingPathComponent("calls.log") }

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let script = dir.appendingPathComponent("op")
        try! """
        #!/bin/sh
        echo "$*" >> "\(log.path)"
        case "$1" in
          read)
            sleep 0.2
            case "$3" in
              op://IT/ts/credential) printf 'tskey-api-fromvault' ;;
              *) echo '[ERROR] 2026/10/10 10:00:00 "nope" isn'"'"'t an item in the "IT" vault' >&2; exit 1 ;;
            esac ;;
          vault) echo '[{"id": "v1", "name": "IT"}, {"id": "v2", "name": "Private"}]' ;;
          item)
            cat > "\(dir.path)/stdin.json"
            echo '{"id": "i1", "fields": [{"id": "credential", "reference": "op://IT/Tailscale ACL – Office/credential"}]}' ;;
        esac
        """.write(to: script, atomically: true, encoding: .utf8)
        chmod(script.path, 0o755)
        OnePassword.cliPathForTests = script.path
        OnePassword.forget()
    }

    override func tearDown() {
        OnePassword.cliPathForTests = nil
        OnePassword.forget()
        try? FileManager.default.removeItem(at: dir)
    }

    func calls() -> [String] {
        ((try? String(contentsOf: log, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
    }

    func testReadsOnceForParallelRequestsAndForgetsOnLock() async throws {
        let values = await withTaskGroup(of: String?.self) { group in
            for _ in 0..<8 { group.addTask { try? await OnePassword.read("op://IT/ts/credential") } }
            var out: [String?] = []
            while let v = await group.next() { out.append(v) }
            return out
        }
        XCTAssertEqual(Set(values.compactMap { $0 }), ["tskey-api-fromvault"])
        XCTAssertEqual(values.count, 8)
        XCTAssertEqual(calls(), ["read --no-newline op://IT/ts/credential"], "one read, one Touch ID prompt")
        _ = try await OnePassword.read("op://IT/ts/credential")
        XCTAssertEqual(calls().count, 1, "kept in memory")
        OnePassword.forget()
        _ = try await OnePassword.read("op://IT/ts/credential")
        XCTAssertEqual(calls().count, 2, "read again after the app locked")
    }

    func testErrorsAreReadable() async {
        do {
            _ = try await OnePassword.read("op://IT/nope/credential")
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error.localizedDescription, #"1Password: "nope" isn't an item in the "IT" vault"#)
        }
        OnePassword.cliPathForTests = "/nonexistent/op"
        do {
            _ = try await OnePassword.read("op://IT/ts/credential")
            XCTFail("expected an error")
        } catch {
            XCTAssertTrue(error.localizedDescription.hasPrefix("The 1Password CLI isn't installed"))
        }
    }

    func testCreateItemSendsTheSecretOnStdinNotArguments() async throws {
        let vaults = try await OnePassword.vaults()
        XCTAssertEqual(vaults, ["IT", "Private"])
        let reference = try await OnePassword.createItem(vault: "IT", title: "Tailscale ACL – Office", secret: "tskey-api-SECRET")
        XCTAssertEqual(reference, "op://IT/Tailscale ACL – Office/credential")
        XCTAssertFalse(calls().joined().contains("SECRET"), "the secret never appears in arguments")
        let item = try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("stdin.json"))) as? [String: Any]
        XCTAssertEqual(item?["category"] as? String, "API_CREDENTIAL")
        XCTAssertEqual(((item?["fields"] as? [[String: Any]])?.first)?["value"] as? String, "tskey-api-SECRET")
        let cached = try await OnePassword.read(reference)
        XCTAssertEqual(cached, "tskey-api-SECRET", "no second Touch ID right after moving")
    }

    func testOnlyRuns1PasswordsSignedBinary() {
        XCTAssertFalse(OnePassword.isSignedBy1Password(dir.appendingPathComponent("op").path), "an unsigned stand-in")
        XCTAssertFalse(OnePassword.isSignedBy1Password("/bin/ls"), "signed, but by Apple")
        if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/op") {
            XCTAssertTrue(OnePassword.isSignedBy1Password("/opt/homebrew/bin/op"))
        }
    }

    func testClientsUseTheSecretAndReportWhereItIs() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data(#"{"keys": [], "expires": "2027-01-01T00:00:00Z"}"#.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "op://IT/ts/credential", session: StubProtocol.session())!
        _ = try await c.policyChanges(days: 1)
        XCTAssertEqual(StubProtocol.requests.first?.request.value(forHTTPHeaderField: "Authorization"), "Bearer tskey-api-fromvault")
        let info = try await c.credentialInfo()
        XCTAssertEqual(info?.reference, "op://IT/ts/credential")

        let plain = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: ["tskey", "api", "x"].joined(separator: "-"), session: StubProtocol.session())!
        let plainInfo = try await plain.credentialInfo()
        XCTAssertNil(plainInfo?.reference)
    }
}
