import SwiftUI
import AppKit

private let gutterWidth: CGFloat = 44

/// HuJSON code editor: NSTextView with regex-based syntax highlighting and a
/// line-number gutter. The gutter is a plain sibling view synced to the scroll
/// position — NSRulerView tiling breaks NSTextView rendering inside SwiftUI
/// on recent macOS, so it is deliberately not used here.
struct CodeEditor: NSViewRepresentable {
    @Binding var text: String

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

        let textView = NSTextView(frame: .zero, textContainer: textContainer)
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
        context.coordinator.highlight(textView)
        return container
    }

    func updateNSView(_ container: NSView, context: Context) {
        guard let textView = context.coordinator.textView else { return }
        if textView.string != text {
            let selection = textView.selectedRange()
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

        init(_ parent: CodeEditor) { self.parent = parent }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
            highlight(textView)
            gutter?.needsDisplay = true
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

/// Draws line numbers for the text view, tracking its scroll position.
final class GutterView: NSView {
    weak var textView: NSTextView?

    override var isFlipped: Bool { true }

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

        func drawNumber(_ n: Int, atLineRect lineRect: NSRect) {
            let y = lineRect.minY + textView.textContainerInset.height - visibleRect.minY
            guard y > -20, y < bounds.height + 20 else { return }
            let label = "\(n)" as NSString
            let size = label.size(withAttributes: attrs)
            label.draw(at: NSPoint(x: bounds.width - size.width - 10, y: y + 1),
                       withAttributes: attrs)
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
