//
// SWGBar / macOS menu bar TLS inspection detector
// Applies and persists the appearance mode
//

import SwiftUI
import AppKit
import SWGBarContracts

extension AppearanceMode {
    /// The AppKit appearance to apply; nil means follow the system.
    /// Derived from the shared name so the tested mapping is the one in effect.
    var nsAppearance: NSAppearance? {
        guard let name = appKitAppearanceName else { return nil }
        return NSAppearance(named: NSAppearance.Name(name))
    }
}

/// Persists the appearance choice and applies it to the whole application.
@MainActor
public final class AppearanceManager: ObservableObject {
    public static let shared = AppearanceManager()

    @Published public private(set) var mode: AppearanceMode

    /// The panel popover, registered by the menu bar controller so that
    /// switching appearance also updates the currently open panel.
    private weak var popover: NSPopover?

    private init() {
        let stored = UserDefaults.standard.string(forKey: AppearanceMode.storageKey) ?? ""
        self.mode = AppearanceMode(rawValue: stored) ?? .system
        apply()
    }

    public func register(popover: NSPopover) {
        self.popover = popover
        apply()
    }

    /// The SwiftUI color scheme for the current mode; nil follows the system.
    public var colorScheme: ColorScheme? {
        switch mode {
        case .system: return nil
        case .dark: return .dark
        case .light: return .light
        }
    }

    /// Advance to the next mode, persist it, and apply it immediately.
    public func cycle() {
        mode = mode.next
        UserDefaults.standard.set(mode.rawValue, forKey: AppearanceMode.storageKey)
        apply()
    }

    /// Setting NSApp.appearance to nil restores the system appearance.
    public func apply() {
        let appearance = mode.nsAppearance
        NSApp.appearance = appearance
        // The popover and its window keep their own appearance, so an already
        // open panel does not follow NSApp.appearance on its own.
        popover?.appearance = appearance
        popover?.contentViewController?.view.appearance = appearance
        for window in NSApp.windows {
            window.appearance = appearance
            window.contentView?.appearance = appearance
        }
    }
}
