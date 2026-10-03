import Foundation

/// Entry point: `tailscale-acl lint|test <file>` runs the app's checks in a
/// terminal or CI without starting the UI; anything else starts the app.
@main
enum Main {
    static func main() {
        if let code = runCommandLine(Array(CommandLine.arguments.dropFirst())) { exit(code) }
        TailscaleACLApp.main()
    }
}

private let usage = """
usage: tailscale-acl lint <policy.hujson>   problems (exit 1 on errors)
       tailscale-acl test <policy.hujson>   problems + the policy's tests (exit 1 on any failure)
Use - to read the policy from standard input.
"""

/// The exit code for a command, or nil when the arguments aren't one
/// (e.g. Finder/Xcode launch flags) and the app should start.
func runCommandLine(_ args: [String], output: (String) -> Void = { print($0) }) -> Int32? {
    guard let command = args.first, ["lint", "test", "help", "--help", "-h"].contains(command) else { return nil }
    guard command == "lint" || command == "test" else {
        output(usage)
        return 0
    }
    guard args.count == 2 else {
        output(usage)
        return 2
    }
    let path = args[1]
    let data = path == "-" ? FileHandle.standardInput.readDataToEndOfFile()
        : FileManager.default.contents(atPath: path)
    guard let data, let text = String(data: data, encoding: .utf8) else {
        output("\(path): cannot read file")
        return 2
    }
    let tree: JSON
    do {
        tree = try HuJSONParser.parse(text)
    } catch let e as HuJSONError {
        output("\(path):\(e.line): error: \(e.message)")
        return 1
    } catch {
        output("\(path): error: \(error)")
        return 1
    }

    let model = PolicyModel(tree: tree)
    let issues = lintPolicy(model)
    for i in issues {
        // file:line: like compilers, so editors and CI can link to it.
        let at = i.path.flatMap(tree.line(at:)).map { "\(path):\($0)" } ?? path
        output("\(at): \(i.severity == .error ? "error" : "warning"): \(i.title): \(i.detail)")
    }
    let errors = issues.filter { $0.severity == .error }.count
    var failed = 0
    if command == "test" {
        let results = Evaluator(model: model).runTests()
        for r in results {
            let at = tree.line(at: "tests[\(r.testIndex)]").map { "\(path):\($0)" } ?? path
            for a in r.assertions where !a.passed {
                output("\(at): FAIL tests[\(r.testIndex)] \(r.src) should \(a.kind == .accept ? "reach" : "not reach") \(a.dst)")
            }
        }
        failed = results.filter { !$0.passed }.count
        output("\(results.count) test\(results.count == 1 ? "" : "s"), \(failed) failed; \(errors) error\(errors == 1 ? "" : "s"), \(issues.count - errors) warning\(issues.count - errors == 1 ? "" : "s")")
    } else {
        output("\(errors) error\(errors == 1 ? "" : "s"), \(issues.count - errors) warning\(issues.count - errors == 1 ? "" : "s")")
    }
    return errors > 0 || failed > 0 ? 1 : 0
}
