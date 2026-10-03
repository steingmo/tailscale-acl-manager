import Foundation

// MARK: - Device posture

/// One posture assertion, e.g. "node:os IN ['macos', 'ios']" or
/// "node:tsVersion >= '1.60'".
struct PostureCondition: Equatable {
    var attribute: String
    var op: String          // ==, !=, <, <=, >, >=, IN, NOT IN, IS SET, NOT SET
    var values: [String]

    init?(_ text: String) {
        let s = text.trimmingCharacters(in: .whitespaces)
        guard let space = s.firstIndex(where: \.isWhitespace) else { return nil }
        attribute = String(s[..<space])
        let rest = s[space...].trimmingCharacters(in: .whitespaces)
        let upper = rest.uppercased()
        if upper == "IS SET" || upper == "NOT SET" {
            op = upper
            values = []
            return
        }
        // Longest operators first, so "<=" isn't read as "<".
        for candidate in ["NOT IN", "IN", "==", "!=", "<=", ">=", "<", ">"] {
            guard upper.hasPrefix(candidate) else { continue }
            let operand = rest.dropFirst(candidate.count).trimmingCharacters(in: .whitespaces)
            if candidate.hasSuffix("IN") {
                guard operand.hasPrefix("["), operand.hasSuffix("]") else { return nil }
                values = operand.dropFirst().dropLast().split(separator: ",").map { Self.unquote(String($0)) }
            } else {
                guard !operand.isEmpty, !operand.hasPrefix("[") else { return nil }
                values = [Self.unquote(operand)]
            }
            op = candidate
            return
        }
        return nil
    }

    private static func unquote(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.count >= 2, let f = t.first, f == t.last, f == "'" || f == "\"" {
            return String(t.dropFirst().dropLast())
        }
        return t
    }

    /// true/false, or nil when the attribute isn't known and `complete` is
    /// false (attributes from a device list cover only os and version).
    func evaluate(_ attrs: [String: String], complete: Bool) -> Bool? {
        guard let value = attrs[attribute] else {
            guard complete else { return nil }
            return op == "NOT SET"
        }
        switch op {
        case "IS SET": return true
        case "NOT SET": return false
        case "==": return value == values[0]
        case "!=": return value != values[0]
        case "IN": return values.contains(value)
        case "NOT IN": return !values.contains(value)
        default:
            let c = compareVersions(value, values[0])
            switch op {
            case "<": return c < 0
            case "<=": return c <= 0
            case ">": return c > 0
            default: return c >= 0
            }
        }
    }
}

/// Numeric, dot-separated comparison ("1.62.1" > "1.9"); missing parts are 0.
func compareVersions(_ a: String, _ b: String) -> Int {
    let pa = a.split(separator: ".").map { Double($0) ?? 0 }
    let pb = b.split(separator: ".").map { Double($0) ?? 0 }
    for i in 0..<max(pa.count, pb.count) {
        let x = i < pa.count ? pa[i] : 0, y = i < pb.count ? pb[i] : 0
        if x != y { return x < y ? -1 : 1 }
    }
    return 0
}

/// A posture holds when every condition does (AND). nil = can't tell.
func postureHolds(_ conditions: [String], attrs: [String: String], complete: Bool) -> Bool? {
    var unknown = false
    for c in conditions {
        guard let condition = PostureCondition(c) else { return false }  // invalid never holds
        switch condition.evaluate(attrs, complete: complete) {
        case false?: return false
        case nil: unknown = true
        case true?: break
        }
    }
    return unknown ? nil : true
}

// MARK: - Expiring rules

/// Rules can carry a "// expires: 2026-11-01" comment line. Problems warns
/// when the date is near or past.
enum RuleExpiry {
    static func date(in comment: String) -> String? {
        let pattern = #/\s*expires:?\s*(\d{4}-\d{2}-\d{2})\s*/#.ignoresCase()
        return comment.wholeMatch(of: pattern).map { String($0.1) }
    }

    static func comment(for date: String) -> String { "expires: \(date)" }

    static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    /// Whole days from `now` until the end of the expiry date's day (negative once past).
    static func daysLeft(_ date: String, now: Date = Date()) -> Int? {
        guard let d = formatter.date(from: date) else { return nil }
        let cal = Calendar.current
        return cal.dateComponents([.day], from: cal.startOfDay(for: now), to: cal.startOfDay(for: d)).day
    }
}
