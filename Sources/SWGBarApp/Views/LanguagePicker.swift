//
// SWGBar / macOS menu bar TLS inspection detector
// 语言选择器：展开后每项用该语言自身书写
//

import SwiftUI
import SWGBarContracts

/// 百分比卡片右上角的语言选择器。
struct LanguagePicker: View {
    @ObservedObject private var l10n = LocalizationManager.shared

    var body: some View {
        Menu {
            // 列表项按惯例用各语言自身书写：English / 简体中文 / 繁體中文 / 日本語 / 한국어
            ForEach(AppLanguage.allCases, id: \.self) { lang in
                Button(action: { l10n.select(lang) }) {
                    HStack {
                        Text(lang.endonym)
                        if lang == l10n.language {
                            Spacer()
                            Image(systemName: "checkmark")
                        }
                    }
                }
            }
        } label: {
            HStack(spacing: 3) {
                Image(systemName: "globe")
                    .font(.system(size: 9))
                Text(l10n.language.endonym)
                    .font(.system(size: 10))
            }
            .foregroundColor(.secondary.opacity(0.7))
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help(L(.languageHintFormat, l10n.language.endonym))
        .accessibilityLabel(L(.language))
        .accessibilityValue(l10n.language.endonym)
        .accessibilityHint(L(.languageSwitchHint))
    }
}
