//
// SWGBar / macOS menu bar TLS inspection detector
// Appearance mode: follow system, force light, or force dark
//

import Foundation

/// Three appearance modes cycled by the footer button, matching the standard macOS convention.
public enum AppearanceMode: String, CaseIterable, Sendable {
    case system
    case dark
    case light

    /// Cycle order: System -> Dark -> Light -> System.
    public var next: AppearanceMode {
        switch self {
        case .system: return .dark
        case .dark: return .light
        case .light: return .system
        }
    }

    /// Label shown next to the version number.
    public var label: String {
        switch self {
        case .system: return "System"
        case .dark: return "Dark"
        case .light: return "Light"
        }
    }

    /// SF Symbol matching the macOS appearance convention.
    public var symbolName: String {
        switch self {
        case .system: return "circle.lefthalf.filled"
        case .dark: return "moon"
        case .light: return "sun.max"
        }
    }

    /// UserDefaults key shared by the app and its tests.
    public static let storageKey = "com.swgbar.appearanceMode"
}
