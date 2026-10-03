import SwiftUI
import AppKit

private let gutterWidth: CGFloat = 44

/// HuJSON code editor: NSTextView with regex-based syntax highlighting and a
/// line-number gutter. The gutter is a plain sibling view synced to the scroll
/// position — NSRulerView tiling breaks NSTextView rendering inside SwiftUI
/// on recent macOS, so it is deliberately not used here.
struct CodeEditor: NSViewRepresentable {
    @Binding var text: String
    /// Problems by 1-based line, drawn in the gutter.
    var markers: [Int: GutterMarker] = [:]
    /// Set to a 1-based line to select and reveal it; cleared once done.
    var lineRequest: Binding<Int?> = .constant(nil)
    /// Names offered while typing inside a string, and shown on hover.
    var vocabulary = EditorVocabulary()

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSView {
        // TextKit 1 stack: the line-number gutter reads layout via
        // NSLayoutManager, and mixing that with a lazily-downgraded TextKit 2
        // view causes blank rendering.
        let textStorage = NSTextStorage()
        let layoutManager = NSLayoutManager()
        textStorage.addLayoutManager(layoutManager)
        let textContainer = NSTextContainer(size: NSSize(
            width: 0, height: CGFloat.greatestFiniteMagnitude
        ))
        textContainer.widthTracksTextView = true
        layoutManager.addTextContainer(textContainer)

        let textView = PolicyTextView(frame: .zero, textContainer: textContainer)
        textView.minSize = .zero
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                  height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]

        textView.delegate = context.coordinator
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.backgroundColor = Theme.editorBackground
        textView.insertionPointColor = .white
        textView.isRichText = false
        textView.allowsUndo = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.textContainerInset = NSSize(width: 8, height: 12)
        textView.selectedTextAttributes = [
            .backgroundColor: NSColor(srgbRed: 0.25, green: 0.32, blue: 0.45, alpha: 0.8)
        ]

        let scrollView = NSScrollView(frame: NSRect(
            x: gutterWidth, y: 0, width: 556, height: 400
        ))
        scrollView.documentView = textView
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = true
        scrollView.backgroundColor = Theme.editorBackground
        scrollView.autoresizingMask = [.width, .height]

        let gutter = GutterView(frame: NSRect(x: 0, y: 0, width: gutterWidth, height: 400))
        gutter.textView = textView
        gutter.autoresizingMask = [.height]

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 600, height: 400))
        container.autoresizesSubviews = true
        container.addSubview(scrollView)
        container.addSubview(gutter)

        // Redraw the gutter whenever the text scrolls.
        scrollView.contentView.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(
            forName: NSView.boundsDidChangeNotification,
            object: scrollView.contentView, queue: .main
        ) { [weak gutter] _ in
            gutter?.needsDisplay = true
        }

        context.coordinator.textView = textView
        context.coordinator.gutter = gutter
        textView.string = text
        textView.vocabulary = vocabulary
        gutter.markers = markers
        context.coordinator.highlight(textView)
        return container
    }

    func updateNSView(_ container: NSView, context: Context) {
        context.coordinator.parent = self
        guard let textView = context.coordinator.textView as? PolicyTextView else { return }
        textView.vocabulary = vocabulary
        if let gutter = context.coordinator.gutter, gutter.markers != markers {
            gutter.markers = markers
            gutter.needsDisplay = true
        }
        if let line = lineRequest.wrappedValue {
            // After this update, so a freshly shown editor has laid out its text.
            DispatchQueue.main.async {
                textView.reveal(line: line)
                lineRequest.wrappedValue = nil
            }
        }
        if textView.string != text {
            let selection = textView.selectedRange()
            // Keep earlier typing undo steps separate from this programmatic replace.
            textView.breakUndoCoalescing()
            textView.string = text
            let limit = (text as NSString).length
            textView.setSelectedRange(NSRange(location: min(selection.location, limit), length: 0))
            context.coordinator.highlight(textView)
            context.coordinator.gutter?.needsDisplay = true
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: CodeEditor
        weak var textView: NSTextView?
        weak var gutter: GutterView?

        /// The user just typed a name character (not a paste, delete, or completion).
        private var typedNameCharacter = false

        init(_ parent: CodeEditor) { self.parent = parent }

        func textView(_ textView: NSTextView, shouldChangeTextIn range: NSRange, replacementString: String?) -> Bool {
            typedNameCharacter = replacementString.map { $0.count == 1 && $0.unicodeScalars.allSatisfy(EditorVocabulary.nameCharacters.contains) } ?? false
            return true
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
            highlight(textView)
            gutter?.needsDisplay = true
            if typedNameCharacter, let tv = textView as? PolicyTextView, tv.hasSuggestions {
                typedNameCharacter = false
                DispatchQueue.main.async { tv.complete(nil) }
            }
        }

        func textView(_ textView: NSTextView, completions words: [String], forPartialWordRange charRange: NSRange,
                      indexOfSelectedItem index: UnsafeMutablePointer<Int>?) -> [String] {
            let partial = (textView.string as NSString).substring(with: charRange)
            return (textView as? PolicyTextView)?.vocabulary.completions(for: partial) ?? []
        }

        func highlight(_ textView: NSTextView) {
            guard let storage = textView.textStorage else { return }
            let ns = textView.string as NSString
            let full = NSRange(location: 0, length: ns.length)

            storage.beginEditing()
            storage.setAttributes([
                .foregroundColor: NSColor(srgbRed: 0.88, green: 0.88, blue: 0.90, alpha: 1),
                .font: NSFont.monospacedSystemFont(ofSize: 13, weight: .regular),
            ], range: full)

            // Palette matched to the Tailscale admin console JSON editor:
            // light-blue keys, green string values, gray comments.
            let keyColor = NSColor(srgbRed: 0.51, green: 0.67, blue: 1.0, alpha: 1)
            let stringColor = NSColor(srgbRed: 0.40, green: 0.76, blue: 0.47, alpha: 1)
            let numberColor = NSColor(srgbRed: 0.40, green: 0.76, blue: 0.47, alpha: 1)
            let commentColor = NSColor(srgbRed: 0.55, green: 0.57, blue: 0.61, alpha: 1)
            let punctColor = NSColor(srgbRed: 0.83, green: 0.83, blue: 0.86, alpha: 1)

            apply(Self.punctuationRegex, color: punctColor, storage: storage, in: full, string: ns)
            apply(Self.numberRegex, color: numberColor, storage: storage, in: full, string: ns)
            apply(Self.stringRegex, color: stringColor, storage: storage, in: full, string: ns)
            apply(Self.keyRegex, color: keyColor, storage: storage, in: full, string: ns, group: 1)
            apply(Self.commentRegex, color: commentColor, storage: storage, in: full, string: ns)
            storage.endEditing()
        }

        private func apply(_ regex: NSRegularExpression, color: NSColor,
                           storage: NSTextStorage, in range: NSRange,
                           string: NSString, group: Int = 0) {
            regex.enumerateMatches(in: string as String, range: range) { match, _, _ in
                if let r = match?.range(at: group), r.location != NSNotFound {
                    storage.addAttribute(.foregroundColor, value: color, range: r)
                }
            }
        }

        private static let stringRegex = try! NSRegularExpression(pattern: #""(?:[^"\\]|\\.)*""#)
        private static let keyRegex = try! NSRegularExpression(pattern: #"("(?:[^"\\]|\\.)*")\s*:"#)
        private static let numberRegex = try! NSRegularExpression(pattern: #"(?<![\w"])-?\d+(?:\.\d+)?"#)
        private static let commentRegex = try! NSRegularExpression(pattern: #"//[^\n]*|/\*[\s\S]*?\*/"#)
        private static let punctuationRegex = try! NSRegularExpression(pattern: #"[{}\[\]:,]"#)
    }
}

struct GutterMarker: Equatable {
    var isError: Bool
    var text: String
}

/// Entity names for completion, and what each one is, for hover.
struct EditorVocabulary {
    var names: [String] = []
    var definitions: [String: String] = [:]

    static let nameCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ":-_@.*"))

    static let autogroups: [(String, String)] = [
        ("autogroup:member", "Users who are members of the tailnet (not shared or tagged devices)"),
        ("autogroup:tagged", "All devices with at least one tag"),
        ("autogroup:self", "The source user's own untagged devices (destination only)"),
        ("autogroup:internet", "Public internet through an exit node (destination only)"),
        ("autogroup:admin", "Users with the Admin role"),
        ("autogroup:owner", "The user with the Owner role"),
        ("autogroup:it-admin", "Users with the IT admin role"),
        ("autogroup:network-admin", "Users with the Network admin role"),
        ("autogroup:billing-admin", "Users with the Billing admin role"),
        ("autogroup:auditor", "Users with the Auditor role"),
        ("autogroup:shared", "Users who accepted a sharing invitation into this tailnet (source only)"),
        ("autogroup:nonroot", "SSH: any login user except root"),
        ("autogroup:danger-all", "Every device, even outside the tailnet — avoid (source only)"),
    ]

    init() {}

    init(_ m: PolicyModel) {
        func list(_ items: [String]) -> String { items.isEmpty ? "none" : items.joined(separator: ", ") }
        for g in m.groupOrder {
            definitions[g] = "\(g) — members: \(list(m.groups[g] ?? []))"
        }
        for t in m.tagOrder {
            definitions[t] = "\(t) — owners: \(list(m.tagOwners[t] ?? []))"
        }
        for h in m.hostOrder {
            definitions[h] = "\(h) = \(m.hosts[h] ?? "")"
            definitions["host:\(h)"] = definitions[h]
        }
        for s in m.ipsetOrder {
            definitions[s] = "\(s) — \(list(m.ipsets[s] ?? []))"
        }
        for p in m.postureOrder {
            definitions[p] = "\(p) — all of: \((m.postures[p] ?? []).joined(separator: "; "))"
        }
        for u in m.allUsers {
            definitions[u] = "\(u) — in \(list(m.groupOrder.filter { m.groups[$0]?.contains(u) == true }))"
        }
        for (a, text) in Self.autogroups { definitions[a] = "\(a) — \(text)" }
        names = m.groupOrder + m.tagOrder + m.hostOrder + m.ipsetOrder + m.postureOrder
            + Self.autogroups.map(\.0) + m.allUsers
    }

    /// Names that extend `partial` (case-insensitive), excluding an exact match.
    func completions(for partial: String) -> [String] {
        let p = partial.lowercased()
        guard !p.isEmpty else { return [] }
        return names.filter { $0.lowercased().hasPrefix(p) && $0 != partial }.uniqued()
    }

    /// What a string under the cursor names, e.g. "tag:db:5432" → tag:db's owners.
    func definition(of token: String) -> String? {
        definitions[token] ?? definitions[DestSpec(token).target]
    }
}

/// The editor's text view: completion of names inside strings, and their
/// definitions as tooltips.
final class PolicyTextView: NSTextView, NSViewToolTipOwner {
    var vocabulary = EditorVocabulary()

    /// The partial name before the caret inside a string literal, or nil.
    private var stringTokenRange: NSRange? {
        let ns = string as NSString
        let caret = selectedRange().location
        guard selectedRange().length == 0 else { return nil }
        var start = caret
        while start > 0 {
            let c = ns.character(at: start - 1)
            if c == 34 { return NSRange(location: start, length: caret - start) }  // opening quote
            guard let scalar = Unicode.Scalar(c), EditorVocabulary.nameCharacters.contains(scalar) else { return nil }
            start -= 1
        }
        return nil
    }

    var hasSuggestions: Bool {
        guard let r = stringTokenRange, r.length >= 2 else { return false }
        return !vocabulary.completions(for: (string as NSString).substring(with: r)).isEmpty
    }

    override var rangeForUserCompletion: NSRange {
        stringTokenRange ?? super.rangeForUserCompletion
    }

    /// Only a chosen completion is inserted: no tentative text while browsing
    /// the list, and nothing on Escape.
    override func insertCompletion(_ word: String, forPartialWordRange charRange: NSRange, movement: Int, isFinal flag: Bool) {
        guard flag, movement != NSTextMovement.cancel.rawValue else { return }
        super.insertCompletion(word, forPartialWordRange: charRange, movement: movement, isFinal: flag)
    }

    /// Select the 1-based line and scroll it into view.
    func reveal(line: Int) {
        let ns = string as NSString
        var range = NSRange(location: 0, length: 0)
        var n = 0
        ns.enumerateSubstrings(in: NSRange(location: 0, length: ns.length), options: [.byLines, .substringNotRequired]) { _, r, _, stop in
            n += 1
            if n == line { range = r; stop.pointee = true }
        }
        guard n == line else { return }
        window?.makeFirstResponder(self)
        setSelectedRange(range)
        scrollRangeToVisible(range)
        showFindIndicator(for: range)
    }

    // MARK: Hover definitions

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        removeAllToolTips()
        addToolTip(bounds, owner: self, userData: nil)
    }

    func view(_ view: NSView, stringForToolTip tag: NSView.ToolTipTag, point: NSPoint,
              userData data: UnsafeMutableRawPointer?) -> String {
        let ns = string as NSString
        let index = characterIndexForInsertion(at: point)
        guard index < ns.length else { return "" }
        let line = ns.lineRange(for: NSRange(location: index, length: 0))
        // The quoted string around the index on this line.
        var start = index, end = index
        while start > line.location, ns.character(at: start - 1) != 34 { start -= 1 }
        while end < NSMaxRange(line), ns.character(at: end) != 34 { end += 1 }
        guard start > line.location, end < NSMaxRange(line) else { return "" }
        let token = ns.substring(with: NSRange(location: start, length: end - start))
        return vocabulary.definition(of: token) ?? ""
    }
}

/// Draws line numbers for the text view, tracking its scroll position, and
/// a dot on lines with problems.
final class GutterView: NSView, NSViewToolTipOwner {
    weak var textView: NSTextView?
    var markers: [Int: GutterMarker] = [:]
    /// Where each visible line number was drawn, for marker tooltips.
    private var drawnLines: [(line: Int, rect: NSRect)] = []

    override var isFlipped: Bool { true }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        removeAllToolTips()
        addToolTip(bounds, owner: self, userData: nil)
    }

    func view(_ view: NSView, stringForToolTip tag: NSView.ToolTipTag, point: NSPoint,
              userData data: UnsafeMutableRawPointer?) -> String {
        guard let line = drawnLines.first(where: { $0.rect.minY <= point.y && point.y < $0.rect.maxY })?.line else { return "" }
        return markers[line]?.text ?? ""
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor(srgbRed: 0.09, green: 0.09, blue: 0.10, alpha: 1).setFill()
        bounds.fill()

        guard let textView,
              let layoutManager = textView.layoutManager,
              let container = textView.textContainer else { return }

        let visibleRect = textView.visibleRect
        let glyphRange = layoutManager.glyphRange(forBoundingRect: visibleRect, in: container)
        let charRange = layoutManager.characterRange(forGlyphRange: glyphRange, actualGlyphRange: nil)
        let content = textView.string as NSString

        var lineNumber = 1
        content.enumerateSubstrings(
            in: NSRange(location: 0, length: charRange.location),
            options: [.byLines, .substringNotRequired]
        ) { _, _, _, _ in lineNumber += 1 }

        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
            .foregroundColor: NSColor(srgbRed: 0.42, green: 0.44, blue: 0.50, alpha: 1),
        ]

        drawnLines = []
        func drawNumber(_ n: Int, atLineRect lineRect: NSRect) {
            let y = lineRect.minY + textView.textContainerInset.height - visibleRect.minY
            guard y > -20, y < bounds.height + 20 else { return }
            let label = "\(n)" as NSString
            let size = label.size(withAttributes: attrs)
            label.draw(at: NSPoint(x: bounds.width - size.width - 10, y: y + 1),
                       withAttributes: attrs)
            drawnLines.append((n, NSRect(x: 0, y: y, width: bounds.width, height: lineRect.height)))
            if let marker = markers[n] {
                (marker.isError ? NSColor.systemRed : NSColor.systemOrange).setFill()
                NSBezierPath(ovalIn: NSRect(x: 5, y: y + lineRect.height / 2 - 3, width: 6, height: 6)).fill()
            }
        }

        var index = charRange.location
        while index < NSMaxRange(charRange) {
            let lineRange = content.lineRange(for: NSRange(location: index, length: 0))
            let glyphs = layoutManager.glyphRange(forCharacterRange: lineRange, actualCharacterRange: nil)
            drawNumber(lineNumber, atLineRect: layoutManager.boundingRect(forGlyphRange: glyphs, in: container))
            lineNumber += 1
            index = NSMaxRange(lineRange)
        }

        // Trailing empty line.
        if content.length == 0 || content.hasSuffix("\n"),
           NSMaxRange(charRange) == content.length {
            let extraRect = layoutManager.extraLineFragmentRect
            if extraRect.height > 0 {
                drawNumber(lineNumber, atLineRect: extraRect)
            }
        }
    }
}
