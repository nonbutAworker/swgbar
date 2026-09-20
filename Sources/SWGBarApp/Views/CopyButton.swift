//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 复制按钮 (CopyButton.swift)
// 就地反馈：点击后图标短暂变为对勾，不打断布局、不弹出横幅
//

import SwiftUI

public struct CopyButton: View {
    private let text: String
    private let tooltip: String
    private let size: CGFloat
    private let padding: CGFloat

    @State private var didCopy: Bool = false

    public init(text: String, tooltip: String, size: CGFloat = 11, padding: CGFloat = 4) {
        self.text = text
        self.tooltip = tooltip
        self.size = size
        self.padding = padding
    }

    public var body: some View {
        Button(action: copy) {
            Image(systemName: didCopy ? "checkmark" : "doc.on.doc")
                .font(.system(size: size, weight: didCopy ? .bold : .regular))
                .foregroundColor(didCopy ? .green : .secondary)
                .frame(width: size + 2, height: size + 2)
                .padding(padding)
                .background(
                    Circle().fill(didCopy ? Color.green.opacity(0.14) : Color.secondary.opacity(0.08))
                )
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .help(didCopy ? "已复制" : tooltip)
        .animation(.easeInOut(duration: 0.15), value: didCopy)
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)

        didCopy = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            didCopy = false
        }
    }
}
