//
// SWGBar / macOS menu bar TLS inspection detector
// Typography, layout, and semantic colors (UITheme.swift)
// System fonts, semantic colors, corner radii, and spacing.
//

import SwiftUI
import SWGBarContracts

public enum UITheme {
    // MARK: - Typography
    public static let bodyFont = Font.system(size: 13, weight: .regular)
    public static let bodyBoldFont = Font.system(size: 13, weight: .semibold)
    public static let subFont = Font.system(size: 11, weight: .regular)
    public static let subBoldFont = Font.system(size: 11, weight: .medium)
    public static let heroPercentageFont = Font.custom("DINAlternate-Bold", size: 84)
    public static let fingerprintFont = Font.system(size: 11, weight: .regular, design: .monospaced)
    public static let titleFont = Font.system(size: 15, weight: .bold)
    
    // MARK: - Layout dimensions
    public static let panelWidth: CGFloat = 360
    public static let panelStandardHeight: CGFloat = 530
    public static let cardCornerRadius: CGFloat = 10
    public static let rowMinHeight: CGFloat = 38
    
    public static let space4: CGFloat = 4
    public static let space8: CGFloat = 8
    public static let space12: CGFloat = 12
    public static let space16: CGFloat = 16
    
    // MARK: - Semantic colors
    // Inspection: orange; suspected: yellow; public: blue-gray; unknown: gray; expected private: green.
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
    
    @MainActor
    public static func badgeText(for identityKind: String) -> String {
        switch identityKind {
        case "inspection": return L(.verdictConfirmed)
        case "suspected": return L(.verdictSuspected)
        case "public": return L(.publicShort)
        default: return L(.verdictUnknown)
        }
    }
    
    // MARK: - Inspection rate gradient: green below 10%, red above 70%
    public static func mitmColor(for ratio: Double?) -> Color {
        guard let ratio = ratio else { return .secondary }
        return Color(nsColor: mitmNSColor(for: ratio))
    }
    
    public static func mitmNSColor(for ratio: Double?) -> NSColor {
        guard let ratio = ratio else { return .secondaryLabelColor }
        let clamped = min(max(ratio, 0.0), 1.0)
        if clamped <= 0.10 {
            // Green at or below 10%.
            return NSColor(calibratedHue: 120.0 / 360.0, saturation: 0.82, brightness: 0.85, alpha: 1.0)
        } else if clamped >= 0.70 {
            // Red at or above 70%.
            return NSColor(calibratedHue: 0.0 / 360.0, saturation: 0.88, brightness: 0.95, alpha: 1.0)
        } else {
            // Interpolate smoothly between 10% and 70%.
            let t = (clamped - 0.10) / 0.60
            let hue = (120.0 * (1.0 - t)) / 360.0
            let sat = 0.82 + t * 0.06
            let bri = 0.85 + t * 0.10
            return NSColor(calibratedHue: hue, saturation: sat, brightness: bri, alpha: 1.0)
        }
    }
    
    // MARK: - Glass materials and highlights
    
    public static let glassCornerRadius: CGFloat = 12
    public static let glassPillCornerRadius: CGFloat = 8
    
    /// Top-edge specular highlight
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

// MARK: - Glass card container (LiquidGlassCardModifier)

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
                    // 1. System material reveals colors from the wallpaper and underlying windows.
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(.ultraThinMaterial)
                    
                    // 2. Inner highlights and a soft gradient provide depth.
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
            // 3. Highlight the border from the upper left toward the lower right.
            .overlay(UITheme.glassBorderStroke(cornerRadius: cornerRadius, isHovered: isHovered))
            // 4. Add a soft ambient shadow.
            .shadow(
                color: Color.black.opacity(isHovered ? 0.08 : 0.04),
                radius: isHovered ? 10 : 6,
                x: 0,
                y: isHovered ? 4 : 2
            )
    }
}

// MARK: - Glass input container (LiquidGlassInputModifier)

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

// MARK: - Glass badge container (LiquidGlassPillModifier)

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

// MARK: - View convenience extensions

extension View {
    /// Apply the standard glass card style.
    public func liquidGlassCard(cornerRadius: CGFloat = UITheme.glassCornerRadius, isHovered: Bool = false) -> some View {
        self.modifier(LiquidGlassCardModifier(cornerRadius: cornerRadius, isHovered: isHovered))
    }
    
    /// Apply the glass input or picker style.
    public func liquidGlassInput(isFocusedOrActive: Bool = false, cornerRadius: CGFloat = 8) -> some View {
        self.modifier(LiquidGlassInputModifier(isFocusedOrActive: isFocusedOrActive, cornerRadius: cornerRadius))
    }
    
    /// Apply the glass pill badge style.
    public func liquidGlassPill(tintColor: Color) -> some View {
        self.modifier(LiquidGlassPillModifier(tintColor: tintColor))
    }
}

