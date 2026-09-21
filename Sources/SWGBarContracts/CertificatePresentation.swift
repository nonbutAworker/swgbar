import Foundation

/// Display-only adaptation. Stored certificate values and trust decisions remain unchanged.
public enum CertificatePresentation {
    public static func isMissing(_ value: String) -> Bool {
        value.isEmpty || value == "<Not present in certificate>" || value == "<未包含在证书中>"
    }

    @MainActor
    private static let dateFormatters: [AppLanguage: DateFormatter] = {
        var result: [AppLanguage: DateFormatter] = [:]
        for language in AppLanguage.allCases {
            let formatter = DateFormatter()
            switch language {
            case .english:
                formatter.locale = Locale(identifier: "en_US_POSIX")
                formatter.dateFormat = "EEEE, MMMM d, yyyy HH:mm:ss"
            case .simplifiedChinese:
                // Exact locale and pattern from the approved 1.5.1 implementation.
                formatter.locale = Locale(identifier: "zh_CN")
                formatter.dateFormat = "yyyy年M月d日EEEE HH:mm:ss"
            case .traditionalChinese:
                formatter.locale = Locale(identifier: "zh_TW")
                formatter.dateFormat = "yyyy年M月d日EEEE HH:mm:ss"
            case .japanese:
                formatter.locale = Locale(identifier: "ja_JP")
                formatter.dateFormat = "yyyy年M月d日EEEE HH:mm:ss"
            case .korean:
                formatter.locale = Locale(identifier: "ko_KR")
                formatter.dateFormat = "yyyy년 M월 d일 EEEE HH:mm:ss"
            }
            result[language] = formatter
        }
        return result
    }()

    @MainActor
    public static func validityDate(_ certificate: CADetail, end: Bool, language: AppLanguage) -> String {
        let ms = end ? certificate.notAfterMs : certificate.notBeforeMs
        if let ms, ms > 0, let formatter = dateFormatters[language] {
            return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(ms) / 1000))
        }
        // Preserve the original missing-field behavior, including legacy validity strings.
        let value = certificate.validityFormatted
        if isMissing(value) || value == "No expiration" || value == "长期有效" { return "" }
        let separator = value.contains(" to ") ? " to " : "至"
        let parts = value.components(separatedBy: separator)
        return (end && parts.count > 1 ? parts[1] : parts[0]).trimmingCharacters(in: .whitespaces)
    }
}
