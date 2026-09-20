//
// SWGBar / macOS menu bar TLS inspection detector
// 界面文案翻译表：英文为基准，另附简中、繁中、日文、韩文
//
// 术语基准（跨页面必须一致）：
//   inspection        中间人检查 / 中間人檢查 / 傍受 / 감청
//   trust chain       信任链 / 信任鏈 / 信頼チェーン / 신뢰 체인
//   certificate       证书 / 憑證 / 証明書 / 인증서
//   root store        根证书库 / 根憑證庫 / ルート証明書ストア / 루트 인증서 저장소
//   handshake         握手 / 交握 / ハンドシェイク / 핸드셰이크
//   probe             探测 / 探測 / プローブ / 프로브
//

import Foundation

/// 界面文案键。用枚举而非裸字符串，漏译会在编译期暴露。
public enum L10nKey: String, CaseIterable, Sendable {
    // 标签页与导航
    case overview, domains, certificates
    case backToDomains, backToCertificates

    // 总览
    case tlsInspectionRate, includesUserLabels
    case inspectionCertificates, noInspectionCertificatesFound

    // 判定结果（Verdict）
    case verdictConfirmed, verdictSuspected, verdictPublicPath
    case verdictExpectedPrivate, verdictUnknown, verdictExcluded

    // 证据来源（EvidenceSource）
    case evidenceSystemFlow, evidenceIndependentProbe, evidenceBrowserRequest

    // 域名列表与筛选
    case filterByCertificateStatus, clearStatusFilter
    case clearCertificateFilter, clearAllFilters
    case noMatchingCertificates, noMatchingCertificateClusters
    case discoveringOutboundConnections
    case publicShort, certificateShort

    // 域名详情
    case networkDetails, endpoint, interfaceLabel, connection
    case activity, requests, lastObserved
    case certificateAndTrust, systemTrust, macosSystemTrust
    case publicPKI, mozillaRootStore, associatedCertificate
    case probeEvidenceStaysLocal
    case copyHostname

    // 证书详情
    case certificateClusterNotFound, affectedDomains, associatedDomains
    case issuedTo, issuedBy, commonName, organization, organizationalUnit
    case validity, validFrom, validUntil
    case publicKey, sha256Fingerprints, copyFullFingerprint
    case notPresentInCertificate
    case certificateDataLocalOnly

    // 引导页
    case welcomeToSWGBar, swgbarIntro
    case permissionsAndProbes
    case systemExtensionPermission, networkFilterPermission
    case browserIntegration, autoProbeNewDomains
    case optional, disabledByDefault
    case stepExtensionDesc, stepFilterDesc, stepProbeDesc
    // 外观模式（按钮上显示）
    case appearanceSystem, appearanceDark, appearanceLight
    // 列表占位符与空态
    case searchDomains, searchCertificateNames, searchCertificates
    case filterCertificates, filterByStatus, allStatuses, allCertificates
    case awaitingProbe, viewAll, copied
    case showDomainDetails, hideDomainDetails
    case publicPathEstablished, notProbedOrPending, notEstablished
    // 监测状态
    case monitoringRunning, monitoringPaused, monitoringAwaitingPermission, monitoringLimited
    case monitoringClickToPause, monitoringClickToResumeFormat
    // 引导页补充
    case stateNotEnabled, enableMonitoring, manualProbesOnly
    case aboutPermissions, aboutPermissionsDesc, openSystemSettings
    // 计数格式
    case outboundDomainsCapturedFormat, matchingDomainsFormat
    case certificateClustersFoundFormat, matchingClustersFormat
    case stateAllowed, stateNotStarted, stateComplete, statePending
    case stateAgreed, stateConsentRequired
    case collectsMetadataOnly, doesNotInstallRootCA

    // 底栏与菜单
    case processedOnThisMac, monitoringStatus
    case appearance, appearanceCycleHint
    case language, languageSwitchHint
    case menuBarNoSamples
    case allStatusesFilter, trustNotEstablished, allCertificatesFilter
    case toastMonitoringEnabled, toastManualOnly
    case menuBarSummaryFormat        // "SWGBar: TLS inspection rate %@/%@ (%@) · Confirmed %@ · Suspected %@"
    case monitoringPausedSuffix
    case quit

    // 带参数的文案
    case copyLabelFormat              // "Copy %@"
    case domainDetailsCountFormat     // "Domain details (%d)"
    case domainsCountFormat           // "%d domains"
    case associatedDomainsCountFormat // "%d associated domains"
    case requestsCountFormat          // "%d requests"
    case scrollForMoreFormat          // "Scroll for more (%d/%d)..."
    case appearanceHintFormat         // "Appearance: %@ - click to switch"
    case languageHintFormat           // "Language: %@ - click to switch"
}

/// 五种语言的文案表。英文为基准，其余按各语言的技术写作习惯翻译。
public enum L10nTable {

    public static func string(_ key: L10nKey, _ language: AppLanguage) -> String {
        let table: [L10nKey: String]
        switch language {
        case .english: table = english
        case .simplifiedChinese: table = simplifiedChinese
        case .traditionalChinese: table = traditionalChinese
        case .japanese: table = japanese
        case .korean: table = korean
        }
        // 缺键时回落英文，保证界面不出现空白
        return table[key] ?? english[key] ?? key.rawValue
    }

    // MARK: - English（基准，保持现有文案不变）

    public static let english: [L10nKey: String] = [
        .showDomainDetails: "Show domain details",
        .hideDomainDetails: "Hide domain details",
        .publicPathEstablished: "Public path established",
        .copied: "Copied",
        .toastMonitoringEnabled: "Local monitoring enabled",
        .toastManualOnly: "Switched to manual probes only",
        .allStatusesFilter: "All statuses",
        .trustNotEstablished: "not established",
        .allCertificatesFilter: "All certificates",
        .appearanceSystem: "System",
        .appearanceDark: "Dark",
        .appearanceLight: "Light",
        .searchDomains: "Search domains...",
        .searchCertificateNames: "Search certificate names...",
        .searchCertificates: "Search certificates...",
        .filterCertificates: "Filter certificates...",
        .filterByStatus: "Filter by status...",
        .allStatuses: "All statuses",
        .allCertificates: "All certificates",
        .awaitingProbe: "Awaiting probe",
        .viewAll: "View all >",
        .notProbedOrPending: "Not probed or pending",
        .notEstablished: "not established",
        .monitoringRunning: "Monitoring",
        .monitoringPaused: "Paused",
        .monitoringAwaitingPermission: "Awaiting permission",
        .monitoringLimited: "Limited monitoring",
        .monitoringClickToPause: "Monitoring - click to pause",
        .monitoringClickToResumeFormat: "%@ · click to resume monitoring",
        .stateNotEnabled: "Not enabled",
        .enableMonitoring: "Enable monitoring",
        .manualProbesOnly: "Manual probes only",
        .aboutPermissions: "About permissions",
        .aboutPermissionsDesc: "SWGBar requests network filter permission; it does not take control of private keys",
        .openSystemSettings: "Open System Settings >",
        .outboundDomainsCapturedFormat: "%d outbound domains captured",
        .matchingDomainsFormat: "%d matching domains",
        .certificateClustersFoundFormat: "%d certificate clusters found",
        .matchingClustersFormat: "%d matching certificate clusters",

        .menuBarSummaryFormat: "SWGBar: TLS inspection rate %@/%@ (%@) · Confirmed %@ · Suspected %@",
        .monitoringPausedSuffix: " · Monitoring paused",
        .stepExtensionDesc: "Request permission for this application's system extension only",
        .stepFilterDesc: "Observe available metadata and allow traffic immediately",
        .stepProbeDesc: "12/minute; 300/hour; 1,000/day",
        .stateAllowed: "Allowed",
        .stateNotStarted: "Not started",
        .stateComplete: "Complete",
        .statePending: "Pending",
        .stateAgreed: "Agreed",
        .stateConsentRequired: "Consent required",

        .menuBarNoSamples: "SWGBar: No eligible request samples yet",
        .overview: "Overview",
        .domains: "Domains",
        .certificates: "Certificates",
        .backToDomains: "Back to domains",
        .backToCertificates: "Back to certificates",

        .tlsInspectionRate: "TLS inspection rate",
        .includesUserLabels: "Includes user labels",
        .inspectionCertificates: "Inspection certificates",
        .noInspectionCertificatesFound: "No inspection or self-signed certificates found",

        .verdictConfirmed: "Confirmed",
        .verdictSuspected: "Suspected",
        .verdictPublicPath: "Public path",
        .verdictExpectedPrivate: "Expected private",
        .verdictUnknown: "Unknown",
        .verdictExcluded: "Excluded",

        .evidenceSystemFlow: "System flow metadata",
        .evidenceIndependentProbe: "Independent application probe",
        .evidenceBrowserRequest: "Observed browser request",

        .filterByCertificateStatus: "Filter by certificate status",
        .clearStatusFilter: "Clear status filter",
        .clearCertificateFilter: "Clear certificate filter",
        .clearAllFilters: "Clear all filters",
        .noMatchingCertificates: "No matching certificates",
        .noMatchingCertificateClusters: "No matching certificate clusters",
        .discoveringOutboundConnections: "Discovering outbound HTTPS connections",
        .publicShort: "Public",
        .certificateShort: "Certificate",

        .networkDetails: "Network details",
        .endpoint: "Endpoint",
        .interfaceLabel: "Interface",
        .connection: "Connection",
        .activity: "Activity",
        .requests: "Requests",
        .lastObserved: "Last observed",
        .certificateAndTrust: "Certificate and trust",
        .systemTrust: "System trust",
        .macosSystemTrust: "macOS System Trust",
        .publicPKI: "Public PKI",
        .mozillaRootStore: "Mozilla Root Store",
        .associatedCertificate: "Associated certificate",
        .probeEvidenceStaysLocal: "Probe evidence stays on this Mac. Read-only analysis.",
        .copyHostname: "Copy hostname",

        .certificateClusterNotFound: "Certificate cluster not found",
        .affectedDomains: "Affected domains",
        .associatedDomains: "Associated domains",
        .issuedTo: "Issued to",
        .issuedBy: "Issued by",
        .commonName: "Common name (CN)",
        .organization: "Organization (O)",
        .organizationalUnit: "Organizational unit (OU)",
        .validity: "Validity",
        .validFrom: "Valid from",
        .validUntil: "Valid until",
        .publicKey: "Public key",
        .sha256Fingerprints: "SHA-256 fingerprints",
        .copyFullFingerprint: "Copy full fingerprint",
        .notPresentInCertificate: "<Not present in certificate>",
        .certificateDataLocalOnly: "Certificate data comes from local keychains and network evidence. Read-only analysis.",

        .welcomeToSWGBar: "Welcome to SWGBar",
        .swgbarIntro: "SWGBar observes outbound connection metadata and probes discovered targets with a TLS handshake to look for inspection certificates.",
        .permissionsAndProbes: "Permissions and probes",
        .systemExtensionPermission: "System extension permission",
        .networkFilterPermission: "Network filter permission",
        .browserIntegration: "Browser integration",
        .autoProbeNewDomains: "Automatically probe new domains",
        .optional: "Optional",
        .disabledByDefault: "Disabled by default; independent probes remain available.",
        .collectsMetadataOnly: "Collects domain and certificate metadata, without saving message bodies.\nActive probes create additional connections.",
        .doesNotInstallRootCA: "Does not install root CAs or change proxy settings.",

        .processedOnThisMac: "Processed on this Mac",
        .monitoringStatus: "Monitoring status",
        .appearance: "Appearance",
        .appearanceCycleHint: "Click to cycle between System, Dark and Light",
        .language: "Language",
        .languageSwitchHint: "Click to switch the interface language",
        .quit: "Quit",

        .copyLabelFormat: "Copy %@",
        .domainDetailsCountFormat: "Domain details (%d)",
        .domainsCountFormat: "%d domains",
        .associatedDomainsCountFormat: "%d associated domains",
        .requestsCountFormat: "%d requests",
        .scrollForMoreFormat: "Scroll for more (%d/%d)...",
        .appearanceHintFormat: "Appearance: %@ - click to switch",
        .languageHintFormat: "Language: %@ - click to switch",
    ]

    // MARK: - 简体中文

    public static let simplifiedChinese: [L10nKey: String] = [
        .showDomainDetails: "展开域名详情",
        .hideDomainDetails: "收起域名详情",
        .publicPathEstablished: "已建立公共路径",
        .copied: "已复制",
        .toastMonitoringEnabled: "本机监测已启用",
        .toastManualOnly: "已切换为仅手动探测",
        .allStatusesFilter: "全部状态",
        .trustNotEstablished: "未建立",
        .allCertificatesFilter: "全部证书",
        .appearanceSystem: "跟随系统",
        .appearanceDark: "深色",
        .appearanceLight: "浅色",
        .searchDomains: "搜索域名…",
        .searchCertificateNames: "搜索证书名称…",
        .searchCertificates: "搜索证书…",
        .filterCertificates: "筛选证书…",
        .filterByStatus: "按状态筛选…",
        .allStatuses: "全部状态",
        .allCertificates: "全部证书",
        .awaitingProbe: "等待探测",
        .viewAll: "查看全部 >",
        .notProbedOrPending: "未探测或等待中",
        .notEstablished: "未建立",
        .monitoringRunning: "监测中",
        .monitoringPaused: "已暂停",
        .monitoringAwaitingPermission: "等待授权",
        .monitoringLimited: "受限监测",
        .monitoringClickToPause: "监测中 · 点击暂停",
        .monitoringClickToResumeFormat: "%@ · 点击恢复监测",
        .stateNotEnabled: "未启用",
        .enableMonitoring: "启用监测",
        .manualProbesOnly: "仅手动探测",
        .aboutPermissions: "关于权限",
        .aboutPermissionsDesc: "SWGBar 仅申请网络过滤权限，不接管私钥",
        .openSystemSettings: "打开系统设置 >",
        .outboundDomainsCapturedFormat: "已捕获 %d 个出站域名",
        .matchingDomainsFormat: "%d 个匹配域名",
        .certificateClustersFoundFormat: "发现 %d 个证书集群",
        .matchingClustersFormat: "%d 个匹配的证书集群",

        .menuBarSummaryFormat: "SWGBar：TLS 检查占比 %@/%@（%@）· 已确认 %@ · 疑似 %@",
        .monitoringPausedSuffix: " · 监测已暂停",
        .stepExtensionDesc: "仅为本应用的系统扩展申请权限",
        .stepFilterDesc: "观察可获取的元数据并立即放行流量",
        .stepProbeDesc: "每分钟 12 次；每小时 300 次；每天 1,000 次",
        .stateAllowed: "已允许",
        .stateNotStarted: "未开始",
        .stateComplete: "已完成",
        .statePending: "待处理",
        .stateAgreed: "已同意",
        .stateConsentRequired: "需要同意",

        .menuBarNoSamples: "SWGBar：暂无符合条件的请求样本",
        .overview: "总览",
        .domains: "域名",
        .certificates: "证书",
        .backToDomains: "返回域名列表",
        .backToCertificates: "返回证书列表",

        .tlsInspectionRate: "TLS 中间人检查占比",
        .includesUserLabels: "含用户标注",
        .inspectionCertificates: "检查证书",
        .noInspectionCertificatesFound: "未发现检查证书或自签名证书",

        .verdictConfirmed: "已确认",
        .verdictSuspected: "疑似",
        .verdictPublicPath: "公共路径",
        .verdictExpectedPrivate: "预期私有",
        .verdictUnknown: "未知",
        .verdictExcluded: "已排除",

        .evidenceSystemFlow: "系统流量元数据",
        .evidenceIndependentProbe: "应用独立探测",
        .evidenceBrowserRequest: "观测到的浏览器请求",

        .filterByCertificateStatus: "按证书状态筛选",
        .clearStatusFilter: "清除状态筛选",
        .clearCertificateFilter: "清除证书筛选",
        .clearAllFilters: "清除全部筛选",
        .noMatchingCertificates: "无匹配的证书",
        .noMatchingCertificateClusters: "无匹配的证书集群",
        .discoveringOutboundConnections: "正在发现出站 HTTPS 连接",
        .publicShort: "公共",
        .certificateShort: "证书",

        .networkDetails: "网络信息",
        .endpoint: "目标地址",
        .interfaceLabel: "出口网卡",
        .connection: "连接方式",
        .activity: "访问统计",
        .requests: "请求频次",
        .lastObserved: "最近观察",
        .certificateAndTrust: "证书与信任",
        .systemTrust: "本机系统校验",
        .macosSystemTrust: "macOS 系统信任",
        .publicPKI: "公共权威验证",
        .mozillaRootStore: "Mozilla 根证书库",
        .associatedCertificate: "关联证书",
        .probeEvidenceStaysLocal: "探测证据保留在本机，仅做只读分析。",
        .copyHostname: "复制域名",

        .certificateClusterNotFound: "未找到该证书集群",
        .affectedDomains: "影响的域名",
        .associatedDomains: "关联域名",
        .issuedTo: "颁发给",
        .issuedBy: "颁发者",
        .commonName: "通用名称 (CN)",
        .organization: "组织 (O)",
        .organizationalUnit: "组织单位 (OU)",
        .validity: "有效期",
        .validFrom: "生效时间",
        .validUntil: "失效时间",
        .publicKey: "公钥",
        .sha256Fingerprints: "SHA-256 指纹",
        .copyFullFingerprint: "复制完整指纹",
        .notPresentInCertificate: "<证书中未提供>",
        .certificateDataLocalOnly: "证书数据来自本机钥匙串与网络证据，仅做只读分析。",

        .welcomeToSWGBar: "欢迎使用 SWGBar",
        .swgbarIntro: "SWGBar 观察出站连接的元数据，并对发现的目标发起 TLS 握手探测，以识别中间人检查证书。",
        .permissionsAndProbes: "权限与探测",
        .systemExtensionPermission: "系统扩展权限",
        .networkFilterPermission: "网络过滤权限",
        .browserIntegration: "浏览器集成",
        .autoProbeNewDomains: "自动探测新域名",
        .optional: "可选",
        .disabledByDefault: "默认关闭，独立探测仍可使用。",
        .collectsMetadataOnly: "仅收集域名与证书元数据，不保存报文内容。\n主动探测会建立额外连接。",
        .doesNotInstallRootCA: "不安装根证书，也不修改代理设置。",

        .processedOnThisMac: "本机处理",
        .monitoringStatus: "监测状态",
        .appearance: "外观",
        .appearanceCycleHint: "点击在跟随系统、深色、浅色之间切换",
        .language: "语言",
        .languageSwitchHint: "点击切换界面语言",
        .quit: "退出",

        .copyLabelFormat: "复制%@",
        .domainDetailsCountFormat: "域名详情（%d）",
        .domainsCountFormat: "%d 个域名",
        .associatedDomainsCountFormat: "关联 %d 个域名",
        .requestsCountFormat: "%d 次请求",
        .scrollForMoreFormat: "滚动查看更多（%d/%d）…",
        .appearanceHintFormat: "外观：%@ · 点击切换",
        .languageHintFormat: "语言：%@ · 点击切换",
    ]

    // MARK: - 繁體中文（臺港資訊術語，非簡體直轉）

    public static let traditionalChinese: [L10nKey: String] = [
        .toastMonitoringEnabled: "本機監測已啟用",
        .toastManualOnly: "已切換為僅手動探測",
        .allStatusesFilter: "全部狀態",
        .trustNotEstablished: "未建立",
        .allCertificatesFilter: "全部憑證",
        .appearanceSystem: "跟隨系統",
        .appearanceDark: "深色",
        .appearanceLight: "淺色",
        .searchDomains: "搜尋網域…",
        .searchCertificateNames: "搜尋憑證名稱…",
        .searchCertificates: "搜尋憑證…",
        .filterCertificates: "篩選憑證…",
        .filterByStatus: "依狀態篩選…",
        .allStatuses: "全部狀態",
        .allCertificates: "全部憑證",
        .awaitingProbe: "等待探測",
        .viewAll: "檢視全部 >",
        .copied: "已複製",
        .showDomainDetails: "展開網域詳細資料",
        .hideDomainDetails: "收合網域詳細資料",
        .publicPathEstablished: "已建立公開路徑",
        .notProbedOrPending: "未探測或等待中",
        .notEstablished: "未建立",
        .monitoringRunning: "監測中",
        .monitoringPaused: "已暫停",
        .monitoringAwaitingPermission: "等待授權",
        .monitoringLimited: "受限監測",
        .monitoringClickToPause: "監測中 · 點按暫停",
        .monitoringClickToResumeFormat: "%@ · 點按恢復監測",
        .stateNotEnabled: "未啟用",
        .enableMonitoring: "啟用監測",
        .manualProbesOnly: "僅手動探測",
        .aboutPermissions: "關於權限",
        .aboutPermissionsDesc: "SWGBar 僅申請網路過濾權限，不接管私密金鑰",
        .openSystemSettings: "開啟系統設定 >",
        .outboundDomainsCapturedFormat: "已擷取 %d 個對外網域",
        .matchingDomainsFormat: "%d 個相符網域",
        .certificateClustersFoundFormat: "找到 %d 個憑證叢集",
        .matchingClustersFormat: "%d 個相符的憑證叢集",

        .menuBarSummaryFormat: "SWGBar：TLS 檢查比例 %@/%@（%@）· 已確認 %@ · 疑似 %@",
        .monitoringPausedSuffix: " · 監測已暫停",
        .stepExtensionDesc: "僅為本應用程式的系統擴充功能申請權限",
        .stepFilterDesc: "觀察可取得的中繼資料並立即放行流量",
        .stepProbeDesc: "每分鐘 12 次；每小時 300 次；每天 1,000 次",
        .stateAllowed: "已允許",
        .stateNotStarted: "未開始",
        .stateComplete: "已完成",
        .statePending: "待處理",
        .stateAgreed: "已同意",
        .stateConsentRequired: "需要同意",

        .menuBarNoSamples: "SWGBar：尚無符合條件的請求樣本",
        .overview: "總覽",
        .domains: "網域",
        .certificates: "憑證",
        .backToDomains: "返回網域列表",
        .backToCertificates: "返回憑證列表",

        .tlsInspectionRate: "TLS 中間人檢查比率",
        .includesUserLabels: "含使用者標註",
        .inspectionCertificates: "檢查憑證",
        .noInspectionCertificatesFound: "未發現檢查憑證或自簽憑證",

        .verdictConfirmed: "已確認",
        .verdictSuspected: "疑似",
        .verdictPublicPath: "公開路徑",
        .verdictExpectedPrivate: "預期私有",
        .verdictUnknown: "未知",
        .verdictExcluded: "已排除",

        .evidenceSystemFlow: "系統流量中繼資料",
        .evidenceIndependentProbe: "應用程式獨立探測",
        .evidenceBrowserRequest: "觀測到的瀏覽器請求",

        .filterByCertificateStatus: "依憑證狀態篩選",
        .clearStatusFilter: "清除狀態篩選",
        .clearCertificateFilter: "清除憑證篩選",
        .clearAllFilters: "清除全部篩選",
        .noMatchingCertificates: "無相符的憑證",
        .noMatchingCertificateClusters: "無相符的憑證叢集",
        .discoveringOutboundConnections: "正在探索對外 HTTPS 連線",
        .publicShort: "公開",
        .certificateShort: "憑證",

        .networkDetails: "網路資訊",
        .endpoint: "目標位址",
        .interfaceLabel: "對外網路介面",
        .connection: "連線方式",
        .activity: "存取統計",
        .requests: "請求次數",
        .lastObserved: "最近觀察",
        .certificateAndTrust: "憑證與信任",
        .systemTrust: "本機系統驗證",
        .macosSystemTrust: "macOS 系統信任",
        .publicPKI: "公開憑證機構驗證",
        .mozillaRootStore: "Mozilla 根憑證庫",
        .associatedCertificate: "關聯憑證",
        .probeEvidenceStaysLocal: "探測證據保留在本機，僅作唯讀分析。",
        .copyHostname: "複製網域名稱",

        .certificateClusterNotFound: "找不到該憑證叢集",
        .affectedDomains: "受影響的網域",
        .associatedDomains: "關聯網域",
        .issuedTo: "發給",
        .issuedBy: "簽發者",
        .commonName: "一般名稱 (CN)",
        .organization: "組織 (O)",
        .organizationalUnit: "組織單位 (OU)",
        .validity: "有效期間",
        .validFrom: "生效時間",
        .validUntil: "失效時間",
        .publicKey: "公開金鑰",
        .sha256Fingerprints: "SHA-256 指紋",
        .copyFullFingerprint: "複製完整指紋",
        .notPresentInCertificate: "<憑證中未提供>",
        .certificateDataLocalOnly: "憑證資料來自本機鑰匙圈與網路證據，僅作唯讀分析。",

        .welcomeToSWGBar: "歡迎使用 SWGBar",
        .swgbarIntro: "SWGBar 觀察對外連線的中繼資料，並對發現的目標發起 TLS 交握探測，以辨識中間人檢查憑證。",
        .permissionsAndProbes: "權限與探測",
        .systemExtensionPermission: "系統擴充功能權限",
        .networkFilterPermission: "網路過濾權限",
        .browserIntegration: "瀏覽器整合",
        .autoProbeNewDomains: "自動探測新網域",
        .optional: "選用",
        .disabledByDefault: "預設關閉，獨立探測仍可使用。",
        .collectsMetadataOnly: "僅蒐集網域與憑證中繼資料，不儲存封包內容。\n主動探測會建立額外連線。",
        .doesNotInstallRootCA: "不安裝根憑證，也不變更代理伺服器設定。",

        .processedOnThisMac: "本機處理",
        .monitoringStatus: "監測狀態",
        .appearance: "外觀",
        .appearanceCycleHint: "點按以在跟隨系統、深色、淺色之間切換",
        .language: "語言",
        .languageSwitchHint: "點按以切換介面語言",
        .quit: "結束",

        .copyLabelFormat: "複製%@",
        .domainDetailsCountFormat: "網域詳細資料（%d）",
        .domainsCountFormat: "%d 個網域",
        .associatedDomainsCountFormat: "關聯 %d 個網域",
        .requestsCountFormat: "%d 次請求",
        .scrollForMoreFormat: "捲動查看更多（%d/%d）…",
        .appearanceHintFormat: "外觀：%@ · 點按切換",
        .languageHintFormat: "語言：%@ · 點按切換",
    ]

    // MARK: - 日本語

    public static let japanese: [L10nKey: String] = [
        .toastMonitoringEnabled: "ローカル監視を有効にしました",
        .toastManualOnly: "手動プローブのみに切り替えました",
        .allStatusesFilter: "すべての状態",
        .showDomainDetails: "ドメイン詳細を表示",
        .hideDomainDetails: "ドメイン詳細を隠す",
        .publicPathEstablished: "公開経路を確立",
        .trustNotEstablished: "未確立",
        .copied: "コピーしました",
        .allCertificatesFilter: "すべての証明書",
        .appearanceSystem: "システム",
        .appearanceDark: "ダーク",
        .appearanceLight: "ライト",
        .searchDomains: "ドメインを検索…",
        .searchCertificateNames: "証明書名を検索…",
        .searchCertificates: "証明書を検索…",
        .filterCertificates: "証明書で絞り込み…",
        .filterByStatus: "状態で絞り込み…",
        .allStatuses: "すべての状態",
        .allCertificates: "すべての証明書",
        .awaitingProbe: "プローブ待ち",
        .viewAll: "すべて表示 >",
        .notProbedOrPending: "未プローブまたは待機中",
        .notEstablished: "未確立",
        .monitoringRunning: "監視中",
        .monitoringPaused: "一時停止中",
        .monitoringAwaitingPermission: "権限待ち",
        .monitoringLimited: "制限付き監視",
        .monitoringClickToPause: "監視中 · クリックで一時停止",
        .monitoringClickToResumeFormat: "%@ · クリックで監視を再開",
        .stateNotEnabled: "未設定",
        .enableMonitoring: "監視を有効にする",
        .manualProbesOnly: "手動プローブのみ",
        .aboutPermissions: "権限について",
        .aboutPermissionsDesc: "SWGBar はネットワークフィルタの権限のみを要求し、秘密鍵は扱いません",
        .openSystemSettings: "システム設定を開く >",
        .outboundDomainsCapturedFormat: "送信ドメイン %d 件を捕捉",
        .matchingDomainsFormat: "一致するドメイン %d 件",
        .certificateClustersFoundFormat: "証明書クラスタ %d 件を検出",
        .matchingClustersFormat: "一致する証明書クラスタ %d 件",

        .menuBarSummaryFormat: "SWGBar：TLS検査の割合 %@/%@（%@）· 確認済み %@ · 疑いあり %@",
        .monitoringPausedSuffix: " · 監視を一時停止中",
        .stepExtensionDesc: "本アプリのシステム機能拡張にのみ権限を要求します",
        .stepFilterDesc: "取得可能なメタデータを観測し、通信は直ちに通過させます",
        .stepProbeDesc: "毎分 12 回／毎時 300 回／毎日 1,000 回",
        .stateAllowed: "許可済み",
        .stateNotStarted: "未開始",
        .stateComplete: "完了",
        .statePending: "保留中",
        .stateAgreed: "同意済み",
        .stateConsentRequired: "同意が必要",

        .menuBarNoSamples: "SWGBar：対象となるリクエストはまだありません",
        .overview: "概要",
        .domains: "ドメイン",
        .certificates: "証明書",
        .backToDomains: "ドメイン一覧に戻る",
        .backToCertificates: "証明書一覧に戻る",

        .tlsInspectionRate: "TLS 傍受率",
        .includesUserLabels: "ユーザー指定を含む",
        .inspectionCertificates: "傍受証明書",
        .noInspectionCertificatesFound: "傍受証明書および自己署名証明書は見つかりません",

        .verdictConfirmed: "確認済み",
        .verdictSuspected: "疑いあり",
        .verdictPublicPath: "公開経路",
        .verdictExpectedPrivate: "想定内のプライベート",
        .verdictUnknown: "不明",
        .verdictExcluded: "対象外",

        .evidenceSystemFlow: "システムフローのメタデータ",
        .evidenceIndependentProbe: "アプリによる独立プローブ",
        .evidenceBrowserRequest: "観測したブラウザリクエスト",

        .filterByCertificateStatus: "証明書の状態で絞り込む",
        .clearStatusFilter: "状態の絞り込みを解除",
        .clearCertificateFilter: "証明書の絞り込みを解除",
        .clearAllFilters: "すべての絞り込みを解除",
        .noMatchingCertificates: "一致する証明書はありません",
        .noMatchingCertificateClusters: "一致する証明書クラスタはありません",
        .discoveringOutboundConnections: "送信 HTTPS 接続を検出しています",
        .publicShort: "公開",
        .certificateShort: "証明書",

        .networkDetails: "ネットワーク情報",
        .endpoint: "接続先アドレス",
        .interfaceLabel: "送信インターフェース",
        .connection: "接続方式",
        .activity: "アクセス統計",
        .requests: "リクエスト数",
        .lastObserved: "最終観測",
        .certificateAndTrust: "証明書と信頼性",
        .systemTrust: "システム検証",
        .macosSystemTrust: "macOS システム信頼",
        .publicPKI: "公開 PKI 検証",
        .mozillaRootStore: "Mozilla ルート証明書ストア",
        .associatedCertificate: "関連する証明書",
        .probeEvidenceStaysLocal: "プローブの証跡はこの Mac 内に保持され、読み取り専用で分析されます。",
        .copyHostname: "ホスト名をコピー",

        .certificateClusterNotFound: "証明書クラスタが見つかりません",
        .affectedDomains: "影響を受けるドメイン",
        .associatedDomains: "関連ドメイン",
        .issuedTo: "発行先",
        .issuedBy: "発行者",
        .commonName: "コモンネーム (CN)",
        .organization: "組織 (O)",
        .organizationalUnit: "組織単位 (OU)",
        .validity: "有効期間",
        .validFrom: "開始日時",
        .validUntil: "終了日時",
        .publicKey: "公開鍵",
        .sha256Fingerprints: "SHA-256 フィンガープリント",
        .copyFullFingerprint: "フィンガープリント全体をコピー",
        .notPresentInCertificate: "<証明書に情報なし>",
        .certificateDataLocalOnly: "証明書データはローカルのキーチェーンとネットワーク証跡に基づき、読み取り専用で分析されます。",

        .welcomeToSWGBar: "SWGBar へようこそ",
        .swgbarIntro: "SWGBar は送信接続のメタデータを観測し、検出した宛先へ TLS ハンドシェイクでプローブを行い、傍受証明書を検出します。",
        .permissionsAndProbes: "権限とプローブ",
        .systemExtensionPermission: "システム機能拡張の権限",
        .networkFilterPermission: "ネットワークフィルタの権限",
        .browserIntegration: "ブラウザ連携",
        .autoProbeNewDomains: "新しいドメインを自動でプローブ",
        .optional: "任意",
        .disabledByDefault: "初期状態では無効です。独立プローブは引き続き利用できます。",
        .collectsMetadataOnly: "ドメインと証明書のメタデータのみを収集し、通信内容は保存しません。\nアクティブプローブは追加の接続を発生させます。",
        .doesNotInstallRootCA: "ルート証明書のインストールやプロキシ設定の変更は行いません。",

        .processedOnThisMac: "この Mac 内で処理",
        .monitoringStatus: "監視状態",
        .appearance: "外観",
        .appearanceCycleHint: "クリックでシステム・ダーク・ライトを切り替え",
        .language: "言語",
        .languageSwitchHint: "クリックで表示言語を切り替え",
        .quit: "終了",

        .copyLabelFormat: "%@をコピー",
        .domainDetailsCountFormat: "ドメイン詳細（%d）",
        .domainsCountFormat: "%d 件のドメイン",
        .associatedDomainsCountFormat: "関連ドメイン %d 件",
        .requestsCountFormat: "%d 件のリクエスト",
        .scrollForMoreFormat: "スクロールしてさらに表示（%d/%d）…",
        .appearanceHintFormat: "外観：%@ · クリックで切り替え",
        .languageHintFormat: "言語：%@ · クリックで切り替え",
    ]

    // MARK: - 한국어

    public static let korean: [L10nKey: String] = [
        .toastMonitoringEnabled: "로컬 모니터링이 활성화되었습니다",
        .toastManualOnly: "수동 프로브 전용으로 전환했습니다",
        .allStatusesFilter: "모든 상태",
        .showDomainDetails: "도메인 세부 정보 표시",
        .hideDomainDetails: "도메인 세부 정보 숨기기",
        .publicPathEstablished: "공개 경로 확립",
        .trustNotEstablished: "미확립",
        .copied: "복사됨",
        .allCertificatesFilter: "모든 인증서",
        .appearanceSystem: "시스템",
        .appearanceDark: "다크",
        .appearanceLight: "라이트",
        .searchDomains: "도메인 검색…",
        .searchCertificateNames: "인증서 이름 검색…",
        .searchCertificates: "인증서 검색…",
        .filterCertificates: "인증서로 필터링…",
        .filterByStatus: "상태로 필터링…",
        .allStatuses: "모든 상태",
        .allCertificates: "모든 인증서",
        .awaitingProbe: "프로브 대기 중",
        .viewAll: "전체 보기 >",
        .notProbedOrPending: "미프로브 또는 대기 중",
        .notEstablished: "미확립",
        .monitoringRunning: "모니터링 중",
        .monitoringPaused: "일시 중지됨",
        .monitoringAwaitingPermission: "권한 대기 중",
        .monitoringLimited: "제한된 모니터링",
        .monitoringClickToPause: "모니터링 중 · 클릭하여 일시 중지",
        .monitoringClickToResumeFormat: "%@ · 클릭하여 모니터링 재개",
        .stateNotEnabled: "비활성",
        .enableMonitoring: "모니터링 활성화",
        .manualProbesOnly: "수동 프로브만",
        .aboutPermissions: "권한 안내",
        .aboutPermissionsDesc: "SWGBar는 네트워크 필터 권한만 요청하며 개인 키를 다루지 않습니다",
        .openSystemSettings: "시스템 설정 열기 >",
        .outboundDomainsCapturedFormat: "아웃바운드 도메인 %d개 포착",
        .matchingDomainsFormat: "일치하는 도메인 %d개",
        .certificateClustersFoundFormat: "인증서 클러스터 %d개 발견",
        .matchingClustersFormat: "일치하는 인증서 클러스터 %d개",

        .menuBarSummaryFormat: "SWGBar: TLS 검사 비율 %@/%@ (%@) · 확인됨 %@ · 의심됨 %@",
        .monitoringPausedSuffix: " · 모니터링 일시 중지됨",
        .stepExtensionDesc: "이 앱의 시스템 확장에 대해서만 권한을 요청합니다",
        .stepFilterDesc: "수집 가능한 메타데이터를 관측하고 트래픽은 즉시 통과시킵니다",
        .stepProbeDesc: "분당 12회, 시간당 300회, 일일 1,000회",
        .stateAllowed: "허용됨",
        .stateNotStarted: "시작 전",
        .stateComplete: "완료",
        .statePending: "대기 중",
        .stateAgreed: "동의함",
        .stateConsentRequired: "동의 필요",

        .menuBarNoSamples: "SWGBar: 아직 해당하는 요청 샘플이 없습니다",
        .overview: "개요",
        .domains: "도메인",
        .certificates: "인증서",
        .backToDomains: "도메인 목록으로",
        .backToCertificates: "인증서 목록으로",

        .tlsInspectionRate: "TLS 감청 비율",
        .includesUserLabels: "사용자 지정 포함",
        .inspectionCertificates: "감청 인증서",
        .noInspectionCertificatesFound: "감청 인증서 또는 자체 서명 인증서를 찾을 수 없습니다",

        .verdictConfirmed: "확인됨",
        .verdictSuspected: "의심됨",
        .verdictPublicPath: "공개 경로",
        .verdictExpectedPrivate: "예상된 사설",
        .verdictUnknown: "알 수 없음",
        .verdictExcluded: "제외됨",

        .evidenceSystemFlow: "시스템 트래픽 메타데이터",
        .evidenceIndependentProbe: "앱 독립 프로브",
        .evidenceBrowserRequest: "관측된 브라우저 요청",

        .filterByCertificateStatus: "인증서 상태로 필터링",
        .clearStatusFilter: "상태 필터 해제",
        .clearCertificateFilter: "인증서 필터 해제",
        .clearAllFilters: "모든 필터 해제",
        .noMatchingCertificates: "일치하는 인증서가 없습니다",
        .noMatchingCertificateClusters: "일치하는 인증서 클러스터가 없습니다",
        .discoveringOutboundConnections: "아웃바운드 HTTPS 연결을 탐지하는 중",
        .publicShort: "공개",
        .certificateShort: "인증서",

        .networkDetails: "네트워크 정보",
        .endpoint: "대상 주소",
        .interfaceLabel: "송신 인터페이스",
        .connection: "연결 방식",
        .activity: "접속 통계",
        .requests: "요청 횟수",
        .lastObserved: "최근 관측",
        .certificateAndTrust: "인증서 및 신뢰",
        .systemTrust: "시스템 검증",
        .macosSystemTrust: "macOS 시스템 신뢰",
        .publicPKI: "공개 PKI 검증",
        .mozillaRootStore: "Mozilla 루트 인증서 저장소",
        .associatedCertificate: "연결된 인증서",
        .probeEvidenceStaysLocal: "프로브 증적은 이 Mac에만 저장되며 읽기 전용으로 분석됩니다.",
        .copyHostname: "호스트 이름 복사",

        .certificateClusterNotFound: "인증서 클러스터를 찾을 수 없습니다",
        .affectedDomains: "영향받는 도메인",
        .associatedDomains: "연결된 도메인",
        .issuedTo: "발급 대상",
        .issuedBy: "발급자",
        .commonName: "일반 이름 (CN)",
        .organization: "조직 (O)",
        .organizationalUnit: "조직 단위 (OU)",
        .validity: "유효 기간",
        .validFrom: "시작 일시",
        .validUntil: "만료 일시",
        .publicKey: "공개 키",
        .sha256Fingerprints: "SHA-256 지문",
        .copyFullFingerprint: "전체 지문 복사",
        .notPresentInCertificate: "<인증서에 없음>",
        .certificateDataLocalOnly: "인증서 데이터는 로컬 키체인과 네트워크 증적에서 가져오며 읽기 전용으로 분석됩니다.",

        .welcomeToSWGBar: "SWGBar에 오신 것을 환영합니다",
        .swgbarIntro: "SWGBar는 아웃바운드 연결의 메타데이터를 관측하고, 발견한 대상에 TLS 핸드셰이크 프로브를 수행하여 감청 인증서를 식별합니다.",
        .permissionsAndProbes: "권한 및 프로브",
        .systemExtensionPermission: "시스템 확장 권한",
        .networkFilterPermission: "네트워크 필터 권한",
        .browserIntegration: "브라우저 연동",
        .autoProbeNewDomains: "새 도메인 자동 프로브",
        .optional: "선택 사항",
        .disabledByDefault: "기본적으로 비활성화되며, 독립 프로브는 계속 사용할 수 있습니다.",
        .collectsMetadataOnly: "도메인과 인증서 메타데이터만 수집하며 통신 내용은 저장하지 않습니다.\n능동 프로브는 추가 연결을 생성합니다.",
        .doesNotInstallRootCA: "루트 인증서를 설치하거나 프록시 설정을 변경하지 않습니다.",

        .processedOnThisMac: "이 Mac에서 처리",
        .monitoringStatus: "모니터링 상태",
        .appearance: "화면 모드",
        .appearanceCycleHint: "클릭하여 시스템·다크·라이트 전환",
        .language: "언어",
        .languageSwitchHint: "클릭하여 인터페이스 언어 전환",
        .quit: "종료",

        .copyLabelFormat: "%@ 복사",
        .domainDetailsCountFormat: "도메인 세부 정보(%d)",
        .domainsCountFormat: "도메인 %d개",
        .associatedDomainsCountFormat: "연결된 도메인 %d개",
        .requestsCountFormat: "요청 %d회",
        .scrollForMoreFormat: "스크롤하여 더 보기(%d/%d)…",
        .appearanceHintFormat: "화면 모드: %@ · 클릭하여 전환",
        .languageHintFormat: "언어: %@ · 클릭하여 전환",
    ]
}
