//
// SWGBar / macOS menu bar TLS inspection detector
// 界面语言：本期支持英文、简体中文、繁体中文、日文、韩文
//

import Foundation

/// 界面语言。放在 Contracts 而非 SWGBarApp，是为了让测试 target 能直接 import。
public enum AppLanguage: String, CaseIterable, Sendable {
    case english = "en"
    case simplifiedChinese = "zh-Hans"
    case traditionalChinese = "zh-Hant"
    case japanese = "ja"
    case korean = "ko"

    /// 默认英文。
    public static let `default`: AppLanguage = .english

    /// 语言列表中显示的名称，按惯例用该语言自身书写。
    public var endonym: String {
        switch self {
        case .english: return "English"
        case .simplifiedChinese: return "简体中文"
        case .traditionalChinese: return "繁體中文"
        case .japanese: return "日本語"
        case .korean: return "한국어"
        }
    }

    /// 菜单按钮上的短标签，宽度受限所以比 endonym 更短。
    public var shortCode: String {
        switch self {
        case .english: return "EN"
        case .simplifiedChinese: return "简"
        case .traditionalChinese: return "繁"
        case .japanese: return "日"
        case .korean: return "한"
        }
    }

    /// UserDefaults 键，与外观偏好共用 com.swgbar. 前缀。
    public static let storageKey = "com.swgbar.appLanguage"

    /// 未知或损坏的持久化值回落到英文。
    public static func from(storedValue: String?) -> AppLanguage {
        guard let raw = storedValue, let lang = AppLanguage(rawValue: raw) else {
            return .default
        }
        return lang
    }
}
