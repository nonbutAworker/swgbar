//
// SWGBar / macOS menu bar TLS inspection detector
// Menu bar status item and popover controller (MenuBarController.swift)
// Use an NSStatusItem, a template icon, and a native context menu without a Dock entry.
//

import Cocoa
import SwiftUI
import Combine
import SWGBarContracts

@MainActor
public final class MenuBarController: NSObject, NSMenuDelegate, NSPopoverDelegate {
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var eventMonitor: Any?
    private var globalMouseMonitor: Any?
    private var localMouseMonitor: Any?
    private var cancellables = Set<AnyCancellable>()
    public let viewModel: AppViewModel
    
    public init(viewModel: AppViewModel = AppViewModel()) {
        self.viewModel = viewModel
        super.init()
        setupStatusItem()
        setupPopover()
        setupEventMonitor()
        setupSubscriptions()
        updateStatusItemDisplay()
    }
    
    private func setupSubscriptions() {
        viewModel.$snapshot
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                self?.updateStatusItemDisplay()
            }
            .store(in: &cancellables)

        // 菜单栏的提示文案也需要随语言切换立即重建
        LocalizationManager.shared.$language
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                self?.updateStatusItemDisplay()
            }
            .store(in: &cancellables)
    }
    
    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem.button {
            button.image = nil
            button.title = "MITM —"
            button.font = NSFont.systemFont(ofSize: 14, weight: .medium)
            button.action = #selector(handleStatusItemClick(_:))
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
            button.setAccessibilityIdentifier("G01_menu_bar_status_item")
        }
    }
    
    private func setupPopover() {
        popover = NSPopover()
        popover.contentSize = NSSize(width: UITheme.panelWidth, height: UITheme.panelStandardHeight)
        popover.behavior = .transient
        popover.animates = true
        popover.delegate = self
        popover.contentViewController = NSHostingController(rootView: MainPanelView(viewModel: viewModel))
    }
    
    private func setupEventMonitor() {
        // Close the panel when Escape is pressed.
        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self = self else { return event }
            if event.keyCode == 53 /* Esc */ {
                if self.popover.isShown {
                    self.closePopover()
                    return nil
                }
            }
            return event
        }
    }
    
    private func startMonitoringOutsideClicks() {
        stopMonitoringOutsideClicks()
        
        // 1. Observe clicks outside the app, including the desktop and other menu items.
        globalMouseMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if self.popover.isShown {
                    self.closePopover()
                }
            }
        }
        
        // 2. Observe app-local clicks outside the popover content.
        localMouseMonitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
            guard let self = self else { return event }
            if self.popover.isShown {
                if let popoverWindow = self.popover.contentViewController?.view.window {
                    if event.window != popoverWindow && event.window != self.statusItem.button?.window {
                        self.closePopover()
                    }
                }
            }
            return event
        }
    }
    
    private func stopMonitoringOutsideClicks() {
        if let monitor = globalMouseMonitor {
            NSEvent.removeMonitor(monitor)
            globalMouseMonitor = nil
        }
        if let monitor = localMouseMonitor {
            NSEvent.removeMonitor(monitor)
            localMouseMonitor = nil
        }
    }
    
    public func popoverDidClose(_ notification: Notification) {
        viewModel.isPanelOpen = false
        stopMonitoringOutsideClicks()
    }
    
    @objc private func handleStatusItemClick(_ sender: NSStatusBarButton) {
        guard let currentEvent = NSApp.currentEvent else { return }
        
        if currentEvent.type == .rightMouseUp {
            // Open the native context menu on right click.
            showContextMenu()
        } else {
            // Toggle the panel on left click.
            togglePopover()
        }
    }
    
    public func togglePopover() {
        if popover.isShown {
            closePopover()
        } else {
            showPopover()
        }
    }
    
    public func showPopover() {
        guard let button = statusItem.button else { return }
        viewModel.isPanelOpen = true
        viewModel.refreshCurrentTabData()
        popover.behavior = .transient
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
        startMonitoringOutsideClicks()
    }
    
    public func closePopover() {
        viewModel.isPanelOpen = false
        stopMonitoringOutsideClicks()
        popover.performClose(nil)
    }
    
    private func showContextMenu() {
        let menu = NSMenu()
        menu.delegate = self
        
        let quitItem = NSMenuItem(title: L(.quit), action: #selector(menuQuit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        
        statusItem.menu = menu
        statusItem.button?.performClick(nil)
    }
    
    public func menuDidClose(_ menu: NSMenu) {
        statusItem.menu = nil // Restore left-click handling.
    }
    
    @objc private func menuQuit() {
        NSApplication.shared.terminate(nil)
    }
    
    public func updateStatusItemDisplay() {
        guard let button = statusItem.button else { return }
        
        guard let _ = viewModel.snapshot.mitmRatio else {
            let title = "MITM —"
            button.title = title
            button.attributedTitle = NSAttributedString(
                string: title,
                attributes: [
                    .foregroundColor: NSColor.secondaryLabelColor,
                    .font: NSFont.systemFont(ofSize: 14, weight: .medium)
                ]
            )
            button.image = nil
            button.toolTip = L(.menuBarNoSamples)
            return
        }
        
        let titleString = viewModel.snapshot.mitmMenuBarString // e.g. "MITM 0.0%"
        
        button.title = titleString
        button.attributedTitle = NSAttributedString(
            string: titleString,
            attributes: [
                .foregroundColor: NSColor.labelColor,
                .font: NSFont.systemFont(ofSize: 14, weight: .semibold)
            ]
        )
        button.image = nil
        
        let y = viewModel.snapshot.mitmHijackedCount
        let x = viewModel.snapshot.mitmTotalCount
        let pct = viewModel.snapshot.mitmPercentageString
        let stateHint = viewModel.snapshot.collectorState == .paused ? L(.monitoringPausedSuffix) : ""
        let summary = L(.menuBarSummaryFormat,
                        "\(y)", "\(x)", pct,
                        "\(viewModel.snapshot.counts.confirmed)",
                        "\(viewModel.snapshot.counts.suspected)")
        button.toolTip = summary + stateHint
    }
}
