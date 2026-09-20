//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 菜单栏状态项与 Popover 控制器 (MenuBarController.swift)
// 遵循技术方案 v1.1 第 15-16 章：NSStatusItem、18x18 模板图、右键原生菜单、无 Dock 入口
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
        // 监听 Esc 按键关闭面板
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
        
        // 1. 全局监听外部点击（捕获其他应用程序、桌面或其他菜单项点击）
        globalMouseMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if self.popover.isShown {
                    self.closePopover()
                }
            }
        }
        
        // 2. 本地监听点击（若点击在本应用内但不在 popover 内容区域）
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
            // 右键打开极简原生菜单 (第 15.3 章)
            showContextMenu()
        } else {
            // 左键开关面板
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
        
        let quitItem = NSMenuItem(title: "退出", action: #selector(menuQuit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        
        statusItem.menu = menu
        statusItem.button?.performClick(nil)
    }
    
    public func menuDidClose(_ menu: NSMenu) {
        statusItem.menu = nil // 恢复左键点击
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
            button.toolTip = "SWGBar: 尚未取得适用请求样本"
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
        let stateHint = viewModel.snapshot.collectorState == .paused ? " · 监测已暂停" : ""
        button.toolTip = "SWGBar: 域名劫持占比 \(y)/\(x) (\(pct)) · 已确认 \(viewModel.snapshot.counts.confirmed) · 疑似 \(viewModel.snapshot.counts.suspected)\(stateHint)"
    }
}
