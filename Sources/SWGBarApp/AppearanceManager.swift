//
// SWGBar / macOS menu bar TLS inspection detector
// Applies and persists the appearance mode
//

import SwiftUI
import AppKit
import SWGBarContracts

extension AppearanceMode {
    /// The AppKit appearance to apply; nil means follow the system.
    var nsAppearance: NSAppearance? {
        switch self {
        case .system: return nil
        case .dark: return NSAppearance(named: .darkAqua)
        case .light: return NSAppearance(named: .aqua)
        }
    }
}

/// Persists the appearance choice and applies it to the whole application.
@MainActor
public final class AppearanceManager: ObservableObject {
    public static let shared = AppearanceManager()

    @Published public private(set) var mode: AppearanceMode

    private init() {
        let stored = UserDefaults.standard.string(forKey: AppearanceMode.storageKey) ?? ""
        self.mode = AppearanceMode(rawValue: stored) ?? .system
        apply()
    }

    /// Advance to the next mode, persist it, and apply it immediately.
    public func cycle() {
        mode = mode.next
        UserDefaults.standard.set(mode.rawValue, forKey: AppearanceMode.storageKey)
        apply()
    }

    /// Setting NSApp.appearance to nil restores the system appearance.
    public func apply() {
        NSApp.appearance = mode.nsAppearance
    }
}
