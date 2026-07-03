import Foundation

// HuJSON = JSON + // and /* */ comments + trailing commas.
// Comments that precede an object member or array element are captured on that
// node so programmatic edits can round-trip without losing them.

indirect enum JSON {
    struct Member {
        var comments: [String]
        var key: String
        var value: JSON
    }
    struct Element {
        var comments: [String]
        var value: JSON
    }

    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([Element])
    case object([Member])
}

extension JSON {
    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    var members: [Member]? {
        get {
            if case .object(let m) = self { return m }
            return nil
        }
        set {
            if let newValue { self = .object(newValue) }
        }
    }

    var elements: [Element]? {
        get {
            if case .array(let e) = self { return e }
            return nil
        }
        set {
            if let newValue { self = .array(newValue) }
        }
    }

    subscript(key: String) -> JSON? {
        get { members?.first(where: { $0.key == key })?.value }
        set {
            guard case .object(var m) = self else { return }
            if let idx = m.firstIndex(where: { $0.key == key }) {
                if let newValue {
                    m[idx].value = newValue
                } else {
                    m.remove(at: idx)
                }
            } else if let newValue {
                m.append(Member(comments: [], key: key, value: newValue))
            }
            self = .object(m)
        }
    }

    /// Array of strings, for src/dst lists and group member lists.
    var stringArray: [String] {
        elements?.compactMap { $0.value.stringValue } ?? []
    }
}

struct HuJSONError: Error {
    var message: String
    var line: Int
}

struct HuJSONParser {
    private let chars: [Character]
    private var pos = 0
    private var line = 1
    private var pendingComments: [String] = []

    init(_ text: String) {
        chars = Array(text)
    }

    static func parse(_ text: String) throws -> JSON {
        var parser = HuJSONParser(text)
        parser.skipTrivia()
        let value = try parser.parseValue()
        parser.skipTrivia()
        if parser.pos < parser.chars.count {
            throw HuJSONError(message: "Unexpected trailing content", line: parser.line)
        }
        return value
    }

    private var current: Character? { pos < chars.count ? chars[pos] : nil }

    private mutating func advance() {
        if pos < chars.count {
            if chars[pos] == "\n" { line += 1 }
            pos += 1
        }
    }

    /// Skips whitespace and comments, accumulating comment text into pendingComments.
    private mutating func skipTrivia() {
        while let c = current {
            if c == " " || c == "\t" || c == "\r" || c == "\n" {
                advance()
            } else if c == "/" && pos + 1 < chars.count && chars[pos + 1] == "/" {
                var text = ""
                advance(); advance()
                while let ch = current, ch != "\n" {
                    text.append(ch)
                    advance()
                }
                pendingComments.append(text.trimmingCharacters(in: .whitespaces))
            } else if c == "/" && pos + 1 < chars.count && chars[pos + 1] == "*" {
                advance(); advance()
                var text = ""
                while pos + 1 < chars.count && !(chars[pos] == "*" && chars[pos + 1] == "/") {
                    text.append(chars[pos])
                    advance()
                }
                advance(); advance()
                pendingComments.append(text.trimmingCharacters(in: .whitespacesAndNewlines))
            } else {
                break
            }
        }
    }

    private mutating func takeComments() -> [String] {
        let c = pendingComments
        pendingComments = []
        return c
    }

    private mutating func parseValue() throws -> JSON {
        skipTrivia()
        guard let c = current else {
            throw HuJSONError(message: "Unexpected end of input", line: line)
        }
        switch c {
        case "{": return try parseObject()
        case "[": return try parseArray()
        case "\"": return .string(try parseString())
        case "t", "f": return try parseBool()
        case "n": return try parseNull()
        default:
            if c == "-" || c.isNumber { return try parseNumber() }
            throw HuJSONError(message: "Unexpected character '\(c)'", line: line)
        }
    }

    private mutating func parseObject() throws -> JSON {
        advance() // {
        var members: [JSON.Member] = []
        while true {
            skipTrivia()
            if current == "}" {
                advance()
                return .object(members)
            }
            guard current == "\"" else {
                throw HuJSONError(message: "Expected \" to begin object key", line: line)
            }
            let comments = takeComments()
            let key = try parseString()
            skipTrivia()
            guard current == ":" else {
                throw HuJSONError(message: "Expected ':' after key \"\(key)\"", line: line)
            }
            advance()
            let value = try parseValue()
            members.append(JSON.Member(comments: comments, key: key, value: value))
            skipTrivia()
            if current == "," {
                advance()
            } else if current != "}" {
                throw HuJSONError(message: "Expected ',' or '}' in object", line: line)
            }
        }
    }

    private mutating func parseArray() throws -> JSON {
        advance() // [
        var elements: [JSON.Element] = []
        while true {
            skipTrivia()
            if current == "]" {
                advance()
                return .array(elements)
            }
            let comments = takeComments()
            let value = try parseValue()
            elements.append(JSON.Element(comments: comments, value: value))
            skipTrivia()
            if current == "," {
                advance()
            } else if current != "]" {
                throw HuJSONError(message: "Expected ',' or ']' in array", line: line)
            }
        }
    }

    private mutating func parseString() throws -> String {
        advance() // opening quote
        var result = ""
        while let c = current {
            if c == "\"" {
                advance()
                return result
            }
            if c == "\\" {
                advance()
                guard let esc = current else { break }
                switch esc {
                case "n": result.append("\n")
                case "t": result.append("\t")
                case "r": result.append("\r")
                case "\"": result.append("\"")
                case "\\": result.append("\\")
                case "/": result.append("/")
                case "u":
                    var hex = ""
                    for _ in 0..<4 {
                        advance()
                        if let h = current { hex.append(h) }
                    }
                    if let code = UInt32(hex, radix: 16), let scalar = Unicode.Scalar(code) {
                        result.append(Character(scalar))
                    }
                default:
                    throw HuJSONError(message: "Invalid escape '\\\(esc)'", line: line)
                }
                advance()
            } else {
                result.append(c)
                advance()
            }
        }
        throw HuJSONError(message: "Unterminated string", line: line)
    }

    private mutating func parseNumber() throws -> JSON {
        var text = ""
        while let c = current, c == "-" || c == "+" || c == "." || c == "e" || c == "E" || c.isNumber {
            text.append(c)
            advance()
        }
        guard let value = Double(text) else {
            throw HuJSONError(message: "Invalid number '\(text)'", line: line)
        }
        return .number(value)
    }

    private mutating func parseBool() throws -> JSON {
        if matches("true") { return .bool(true) }
        if matches("false") { return .bool(false) }
        throw HuJSONError(message: "Invalid literal", line: line)
    }

    private mutating func parseNull() throws -> JSON {
        if matches("null") { return .null }
        throw HuJSONError(message: "Invalid literal", line: line)
    }

    private mutating func matches(_ word: String) -> Bool {
        let w = Array(word)
        guard pos + w.count <= chars.count else { return false }
        for (i, c) in w.enumerated() where chars[pos + i] != c { return false }
        for _ in w { advance() }
        return true
    }
}

enum HuJSONSerializer {
    static func serialize(_ json: JSON) -> String {
        var out = ""
        write(json, indent: 0, into: &out)
        out.append("\n")
        return out
    }

    private static func pad(_ n: Int) -> String { String(repeating: "  ", count: n) }

    private static func write(_ json: JSON, indent: Int, into out: inout String) {
        switch json {
        case .string(let s):
            out.append(encodeString(s))
        case .number(let n):
            if n == n.rounded() && abs(n) < 1e15 {
                out.append(String(Int64(n)))
            } else {
                out.append(String(n))
            }
        case .bool(let b):
            out.append(b ? "true" : "false")
        case .null:
            out.append("null")
        case .array(let elements):
            writeArray(elements, indent: indent, into: &out)
        case .object(let members):
            writeObject(members, indent: indent, into: &out)
        }
    }

    private static func isScalar(_ json: JSON) -> Bool {
        switch json {
        case .array, .object: return false
        default: return true
        }
    }

    private static func writeArray(_ elements: [JSON.Element], indent: Int, into out: inout String) {
        if elements.isEmpty {
            out.append("[]")
            return
        }
        // Inline short scalar arrays with no comments (e.g. src/dst lists).
        let allScalar = elements.allSatisfy { isScalar($0.value) && $0.comments.isEmpty }
        if allScalar {
            var inline = "["
            for (i, e) in elements.enumerated() {
                if i > 0 { inline.append(", ") }
                write(e.value, indent: indent, into: &inline)
            }
            inline.append("]")
            if inline.count <= 76 {
                out.append(inline)
                return
            }
        }
        out.append("[\n")
        for (i, e) in elements.enumerated() {
            if !e.comments.isEmpty && i > 0 { out.append("\n") }
            for comment in e.comments {
                out.append(pad(indent + 1) + "// " + comment + "\n")
            }
            out.append(pad(indent + 1))
            write(e.value, indent: indent + 1, into: &out)
            out.append(",\n")
        }
        out.append(pad(indent) + "]")
    }

    private static func writeObject(_ members: [JSON.Member], indent: Int, into out: inout String) {
        if members.isEmpty {
            out.append("{}")
            return
        }
        out.append("{\n")
        for (i, m) in members.enumerated() {
            if !m.comments.isEmpty && i > 0 { out.append("\n") }
            if indent == 0 && i > 0 && m.comments.isEmpty { out.append("\n") }
            for comment in m.comments {
                out.append(pad(indent + 1) + "// " + comment + "\n")
            }
            out.append(pad(indent + 1) + encodeString(m.key) + ": ")
            write(m.value, indent: indent + 1, into: &out)
            out.append(",\n")
        }
        out.append(pad(indent) + "}")
    }

    private static func encodeString(_ s: String) -> String {
        var out = "\""
        for c in s {
            switch c {
            case "\"": out.append("\\\"")
            case "\\": out.append("\\\\")
            case "\n": out.append("\\n")
            case "\t": out.append("\\t")
            case "\r": out.append("\\r")
            default: out.append(c)
            }
        }
        out.append("\"")
        return out
    }
}
