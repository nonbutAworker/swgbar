//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 首次运行与分步授权 (OnboardingView.swift)
// 遵循技术方案 v1.1 第 16.2 章与图 16-1 视觉设计
//

import SwiftUI
import SWGBarContracts

public struct OnboardingView: View {
    @ObservedObject var vm: AppViewModel
    @State private var step1Done: Bool = false
    @State private var step2Done: Bool = false
    @State private var step3Agreed: Bool = false
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 14) {
                // 顶部说明
                VStack(alignment: .leading, spacing: 6) {
                    Text("开始使用 SWGBar")
                        .font(.system(size: 17, weight: .bold))
                    
                    Text("采集域名与证书元数据；不保存正文。\n主动探测会产生额外连接。")
                        .font(UITheme.bodyFont)
                        .foregroundColor(.primary)
                    
                    Text("不安装根 CA，不修改现有代理策略。")
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                }
                
                // 授权与探测分步卡片
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("授权与探测")
                            .font(UITheme.subBoldFont)
                        Spacer()
                        Text(step1Done && step2Done ? "已授权" : "尚未启用")
                            .font(.system(size: 10))
                            .foregroundColor(step1Done ? .green : .secondary)
                    }
                    
                    stepRow(index: 1, title: "系统扩展授权", desc: "只请求本产品的系统扩展权限", state: step1Done ? "已授权" : "未开始", ok: step1Done) {
                        step1Done = true
                    }
                    
                    stepRow(index: 2, title: "网络过滤授权", desc: "仅观察可用元数据，立即放行", state: step2Done ? "已完成" : "待完成", ok: step2Done) {
                        step2Done = true
                    }
                    
                    stepRow(index: 3, title: "自动探测新域名", desc: "12 次/分钟；300 次/小时；1000 次/日", state: step3Agreed ? "已同意" : "待同意", ok: step3Agreed) {
                        step3Agreed.toggle()
                    }
                }
                .padding(12)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(UITheme.cardCornerRadius)
                
                // 浏览器增强 (可选)
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("浏览器增强")
                            .font(UITheme.subBoldFont)
                        Spacer()
                        Text("可选")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    Text("默认关闭；不影响基础版独立探测。")
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(UITheme.cardCornerRadius)
                
                // 操作按钮
                HStack(spacing: 10) {
                    Button("启用本机监测") {
                        step1Done = true
                        step2Done = true
                        vm.configuration.systemCaptureEnabled = true
                        vm.configuration.autoProbeEnabled = step3Agreed
                        vm.showingOnboarding = false
                        vm.showToast("本机监测已成功启用")
                    }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity)
                    
                    Button("仅手动探测") {
                        vm.configuration.systemCaptureEnabled = false
                        vm.configuration.autoProbeEnabled = false
                        vm.showingOnboarding = false
                        vm.showToast("已切换为仅手动探测模式")
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                }
                .padding(.top, 4)
                
                // 辅助链接
                HStack {
                    Button("查看授权说明") {
                        vm.showToast("SWGBar 仅请求 Network Extension 过滤权限，不接管私钥")
                    }
                    .buttonStyle(.plain)
                    .font(UITheme.subFont)
                    .foregroundColor(.blue)
                    
                    Spacer()
                    
                    Button("打开系统设置 >") {
                        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    .buttonStyle(.plain)
                    .font(UITheme.subFont)
                    .foregroundColor(.blue)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
    }
    
    private func stepRow(index: Int, title: String, desc: String, state: String, ok: Bool, onAction: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                Circle()
                    .fill(ok ? Color.green : Color.blue.opacity(0.15))
                    .frame(width: 18, height: 18)
                Text("\(index)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(ok ? .white : .blue)
            }
            .padding(.top, 1)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(UITheme.bodyBoldFont)
                Text(desc)
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Button(state) {
                onAction()
            }
            .buttonStyle(.bordered)
            .font(.system(size: 10))
        }
        .padding(.vertical, 2)
    }
}
