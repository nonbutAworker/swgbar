//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 视觉规范与语义色彩 (UITheme.swift)
// 遵循技术方案 v1.1 第 25 章：系统字体、语义色彩、圆角与间距规范
//

import SwiftUI
import SWGBarContracts

public enum UITheme {
    // MARK: - 字体规范 (第 25.1 章)
    public static let bodyFont = Font.system(size: 13, weight: .regular)
    public static let bodyBoldFont = Font.system(size: 13, weight: .semibold)
    public static let subFont = Font.system(size: 11, weight: .regular)
    public static let subBoldFont = Font.system(size: 11, weight: .medium)
    public static let heroPercentageFont = Font.custom("DINAlternate-Bold", size: 84)
    public static let fingerprintFont = Font.system(size: 11, weight: .regular, design: .monospaced)
    public static let titleFont = Font.system(size: 15, weight: .bold)
    
    // MARK: - 尺寸规范 (第 15.2, 25.1 章)
    public static let panelWidth: CGFloat = 360
    public static let panelStandardHeight: CGFloat = 530
    public static let cardCornerRadius: CGFloat = 10
    public static let rowMinHeight: CGFloat = 38
    
    public static let space4: CGFloat = 4
    public static let space8: CGFloat = 8
    public static let space12: CGFloat = 12
    public static let space16: CGFloat = 16
    
    // MARK: - 语义色彩 (第 25.1 章)
    // 检查身份橙、疑似黄、公共路径中性蓝灰、未知灰、预期私有绿
    public static let colorConfirmed = Color.orange
    public static let colorSuspected = Color.yellow
    public static let colorPublicPath = Color(red: 0.35, green: 0.45, blue: 0.6)
    public static let colorExpectedPrivate = Color.teal
    public static let colorUnknown = Color.gray
    public static let colorExcluded = Color.secondary
    
    public static func color(for verdict: Verdict) -> Color {
        switch verdict {
        case .confirmedInspection: return colorConfirmed
        case .suspectedInspection: return colorSuspected
        case .publicPath: return colorPublicPath
        case .unknown, .expectedPrivate: return colorUnknown
        case .excluded: return colorExcluded
        }
    }
    
    public static func color(for identityKind: String) -> Color {
        switch identityKind {
        case "inspection": return colorConfirmed
        case "suspected": return colorSuspected
        case "public": return colorPublicPath
        default: return colorUnknown
        }
    }
    
    public static func badgeText(for identityKind: String) -> String {
        switch identityKind {
        case "inspection": return "确认"
        case "suspected": return "疑似"
        case "public": return "公共"
        default: return "未知"
        }
    }
    
    // MARK: - 劫持比例渐变色 (10% 以内绿色，70% 以上红色，中间平滑渐变)
    public static func mitmColor(for ratio: Double?) -> Color {
        guard let ratio = ratio else { return .secondary }
        return Color(nsColor: mitmNSColor(for: ratio))
    }
    
    public static func mitmNSColor(for ratio: Double?) -> NSColor {
        guard let ratio = ratio else { return .secondaryLabelColor }
        let clamped = min(max(ratio, 0.0), 1.0)
        if clamped <= 0.10 {
            // 10% 以内绿色
            return NSColor(calibratedHue: 120.0 / 360.0, saturation: 0.82, brightness: 0.85, alpha: 1.0)
        } else if clamped >= 0.70 {
            // 70% 以上红色
            return NSColor(calibratedHue: 0.0 / 360.0, saturation: 0.88, brightness: 0.95, alpha: 1.0)
        } else {
            // 10% ~ 70% 之间平滑渐变
            let t = (clamped - 0.10) / 0.60
            let hue = (120.0 * (1.0 - t)) / 360.0
            let sat = 0.82 + t * 0.06
            let bri = 0.85 + t * 0.10
            return NSColor(calibratedHue: hue, saturation: sat, brightness: bri, alpha: 1.0)
        }
    }
    
    // MARK: - Liquid Glass 视觉材质与高光规范 (macOS Liquid Glass Design System)
    
    public static let glassCornerRadius: CGFloat = 12
    public static let glassPillCornerRadius: CGFloat = 8
    
    /// 液体玻璃顶部受光高光描边 (Specular Edge Rim)
    public static func glassBorderStroke(cornerRadius: CGFloat = glassCornerRadius, isHovered: Bool = false) -> some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .strokeBorder(
                LinearGradient(
                    colors: [
                        Color.white.opacity(isHovered ? 0.55 : 0.38),
                        Color.white.opacity(isHovered ? 0.22 : 0.12),
                        Color.white.opacity(0.04),
                        Color.black.opacity(0.06)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                lineWidth: 0.85
            )
    }
}

// MARK: - Liquid Glass 拟真透亮卡片容器 (LiquidGlassCardModifier)

public struct LiquidGlassCardModifier: ViewModifier {
    var cornerRadius: CGFloat
    var isHovered: Bool
    
    public init(cornerRadius: CGFloat = UITheme.glassCornerRadius, isHovered: Bool = false) {
        self.cornerRadius = cornerRadius
        self.isHovered = isHovered
    }
    
    public func body(content: Content) -> some View {
        content
            .background(
                ZStack {
                    // 1. 系统底层超轻毛玻璃材质（透过壁纸和下层窗口色彩）
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(.ultraThinMaterial)
                    
                    // 2. 拟真流体玻璃内层光斑与漫反射渐变
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [
                                    Color.white.opacity(isHovered ? 0.18 : 0.08),
                                    Color.white.opacity(isHovered ? 0.06 : 0.02),
                                    Color.black.opacity(0.03)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                }
            )
            // 3. 顶部左上向右下的流体折射高光边框
            .overlay(UITheme.glassBorderStroke(cornerRadius: cornerRadius, isHovered: isHovered))
            // 4. 柔和扩散环境光投影
            .shadow(
                color: Color.black.opacity(isHovered ? 0.08 : 0.04),
                radius: isHovered ? 10 : 6,
                x: 0,
                y: isHovered ? 4 : 2
            )
    }
}

// MARK: - Liquid Glass 输入控件容器修饰器 (LiquidGlassInputModifier)

public struct LiquidGlassInputModifier: ViewModifier {
    var isFocusedOrActive: Bool
    var cornerRadius: CGFloat
    
    public init(isFocusedOrActive: Bool = false, cornerRadius: CGFloat = 8) {
        self.isFocusedOrActive = isFocusedOrActive
        self.cornerRadius = cornerRadius
    }
    
    public func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(.ultraThinMaterial.opacity(0.85))
                    .overlay(
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(Color(NSColor.controlBackgroundColor).opacity(0.45))
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(
                        LinearGradient(
                            colors: isFocusedOrActive ? [
                                Color.accentColor.opacity(0.8),
                                Color.accentColor.opacity(0.4)
                            ] : [
                                Color.white.opacity(0.35),
                                Color.white.opacity(0.12),
                                Color.black.opacity(0.06)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: isFocusedOrActive ? 1.2 : 0.8
                    )
            )
            .shadow(
                color: isFocusedOrActive ? Color.accentColor.opacity(0.15) : Color.black.opacity(0.02),
                radius: isFocusedOrActive ? 4 : 2,
                x: 0,
                y: 1
            )
    }
}

// MARK: - Liquid Glass 晶莹胶囊徽章修饰器 (LiquidGlassPillModifier)

public struct LiquidGlassPillModifier: ViewModifier {
    var tintColor: Color
    
    public init(tintColor: Color) {
        self.tintColor = tintColor
    }
    
    public func body(content: Content) -> some View {
        content
            .background(
                Capsule()
                    .fill(tintColor.opacity(0.14))
                    .background(.ultraThinMaterial, in: Capsule())
            )
            .overlay(
                Capsule()
                    .strokeBorder(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(0.45),
                                tintColor.opacity(0.35),
                                tintColor.opacity(0.1)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 0.8
                    )
            )
    }
}

// MARK: - View 便捷扩展

extension View {
    /// 应用标准 Liquid Glass 玻璃卡片样式
    public func liquidGlassCard(cornerRadius: CGFloat = UITheme.glassCornerRadius, isHovered: Bool = false) -> some View {
        self.modifier(LiquidGlassCardModifier(cornerRadius: cornerRadius, isHovered: isHovered))
    }
    
    /// 应用 Liquid Glass 输入框/选择器样式
    public func liquidGlassInput(isFocusedOrActive: Bool = false, cornerRadius: CGFloat = 8) -> some View {
        self.modifier(LiquidGlassInputModifier(isFocusedOrActive: isFocusedOrActive, cornerRadius: cornerRadius))
    }
    
    /// 应用 Liquid Glass 晶莹药丸胶囊徽章样式
    public func liquidGlassPill(tintColor: Color) -> some View {
        self.modifier(LiquidGlassPillModifier(tintColor: tintColor))
    }
}

