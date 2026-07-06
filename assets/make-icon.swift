// Renders the app icon PNG: swift assets/make-icon.swift <out.png>
import AppKit

let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)
image.lockFocus()

let rect = NSRect(x: 64, y: 64, width: 896, height: 896)
let path = NSBezierPath(roundedRect: rect, xRadius: 200, yRadius: 200)
NSGradient(
    starting: NSColor(srgbRed: 0.13, green: 0.14, blue: 0.16, alpha: 1),
    ending: NSColor(srgbRed: 0.07, green: 0.08, blue: 0.09, alpha: 1)
)?.draw(in: path, angle: -90)

if let shield = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(.init(pointSize: 480, weight: .medium)
        .applying(.init(paletteColors: [NSColor(srgbRed: 0.19, green: 0.83, blue: 0.48, alpha: 1)]))) {
    let s = shield.size
    shield.draw(in: NSRect(x: (size.width - s.width) / 2, y: (size.height - s.height) / 2,
                           width: s.width, height: s.height))
}

image.unlockFocus()
let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
rep.size = size
try! rep.representation(using: .png, properties: [:])!
    .write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
