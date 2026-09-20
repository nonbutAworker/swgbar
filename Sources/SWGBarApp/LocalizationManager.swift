//
// SWGBar / macOS menu bar TLS inspection detector
// 界面语言：持久化选择并驱动界面刷新
//

import SwiftUI
import SWGBarContracts

/// 保存语言选择并在切换时刷新界面。
@MainActor
public final class LocalizationManager: ObservableObject {
    public static let shared = LocalizationManager()

    @Published public private(set) var language: AppLanguage

    private init() {
        self.language = AppLanguage.from(
            storedValue: UserDefaults.standard.string(forKey: AppLanguage.storageKey)
        )
    }

    /// 选择指定语言并立即持久化；@Published 变更会驱动所有引用处重绘。
    public func select(_ language: AppLanguage) {
        guard language != self.language else { return }
        self.language = language
        UserDefaults.standard.set(language.rawValue, forKey: AppLanguage.storageKey)
    }

    /// 按当前语言取文案。
    public func string(_ key: L10nKey) -> String {
        L10nTable.string(key, language)
    }

    /// 带参数的文案，占位符顺序由各语言的译文自行决定。
    public func string(_ key: L10nKey, _ args: CVarArg...) -> String {
        String(format: L10nTable.string(key, language), arguments: args)
    }
}

/// 视图内的取值简写：`L(.overview)`。
@MainActor
public func L(_ key: L10nKey) -> String {
    LocalizationManager.shared.string(key)
}

/// 带参数版本：`L(.domainsCountFormat, 12)`。
@MainActor
public func L(_ key: L10nKey, _ args: CVarArg...) -> String {
    String(format: L10nTable.string(key, LocalizationManager.shared.language), arguments: args)
}

// MARK: - 判定结果与证据来源的本地化

public extension Verdict {
    /// 判定结果的本地化短标签。
    @MainActor
    var localizedLabel: String {
        switch self {
        case .confirmedInspection: return L(.verdictConfirmed)
        case .suspectedInspection: return L(.verdictSuspected)
        case .publicPath: return L(.verdictPublicPath)
        case .expectedPrivate: return L(.verdictExpectedPrivate)
        case .unknown: return L(.verdictUnknown)
        case .excluded: return L(.verdictExcluded)
        }
    }
}

public extension EvidenceSource {
    /// 证据来源的本地化名称。
    @MainActor
    var localizedName: String {
        switch self {
        case .systemFlow: return L(.evidenceSystemFlow)
        case .nativeProbe: return L(.evidenceIndependentProbe)
        case .browserRequest: return L(.evidenceBrowserRequest)
        }
    }
}

public extension AppearanceMode {
    /// 外观模式的本地化标签。原 label 保留英文，供日志等非界面场景使用。
    @MainActor
    var localizedLabel: String {
        switch self {
        case .system: return L(.appearanceSystem)
        case .dark: return L(.appearanceDark)
        case .light: return L(.appearanceLight)
        }
    }
}
