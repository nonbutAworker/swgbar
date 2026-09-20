//
// SWGBar / macOS menu bar TLS inspection detector
// First-run permissions and probe preferences (OnboardingView.swift)
// Step-by-step introduction and permission controls.
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
                // Introduction
                VStack(alignment: .leading, spacing: 6) {
                    Text("Welcome to SWGBar")
                        .font(.system(size: 17, weight: .bold))
                    
                    Text("Collects domain and certificate metadata, without saving message bodies.\nActive probes create additional connections.")
                        .font(UITheme.bodyFont)
                        .foregroundColor(.primary)
                    
                    Text("Does not install root CAs or change proxy settings.")
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                }
                
                // Permission and probe steps
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Permissions and probes")
                            .font(UITheme.subBoldFont)
                        Spacer()
                        Text(step1Done && step2Done ? "Allowed" : "Not enabled")
                            .font(.system(size: 10))
                            .foregroundColor(step1Done ? .green : .secondary)
                    }
                    
                    stepRow(index: 1, title: "System extension permission", desc: "Request permission for this application's system extension only", state: step1Done ? "Allowed" : "Not started", ok: step1Done) {
                        step1Done = true
                    }
                    
                    stepRow(index: 2, title: "Network filter permission", desc: "Observe available metadata and allow traffic immediately", state: step2Done ? "Complete" : "Pending", ok: step2Done) {
                        step2Done = true
                    }
                    
                    stepRow(index: 3, title: "Automatically probe new domains", desc: "12/minute; 300/hour; 1,000/day", state: step3Agreed ? "Agreed" : "Consent required", ok: step3Agreed) {
                        step3Agreed.toggle()
                    }
                }
                .padding(12)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(UITheme.cardCornerRadius)
                
                // Optional browser integration
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Browser integration")
                            .font(UITheme.subBoldFont)
                        Spacer()
                        Text("Optional")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    Text("Disabled by default; independent probes remain available.")
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(UITheme.cardCornerRadius)
                
                // Action buttons
                HStack(spacing: 10) {
                    Button("Enable monitoring") {
                        step1Done = true
                        step2Done = true
                        vm.configuration.systemCaptureEnabled = true
                        vm.configuration.autoProbeEnabled = step3Agreed
                        vm.showingOnboarding = false
                        vm.showToast("Local monitoring enabled")
                    }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity)
                    
                    Button("Manual probes only") {
                        vm.configuration.systemCaptureEnabled = false
                        vm.configuration.autoProbeEnabled = false
                        vm.showingOnboarding = false
                        vm.showToast("Switched to manual probes only")
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                }
                .padding(.top, 4)
                
                // Supporting links
                HStack {
                    Button("About permissions") {
                        vm.showToast("SWGBar requests network filter permission; it does not take control of private keys")
                    }
                    .buttonStyle(.plain)
                    .font(UITheme.subFont)
                    .foregroundColor(.blue)
                    
                    Spacer()
                    
                    Button("Open System Settings >") {
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
