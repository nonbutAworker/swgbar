// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SWGBar",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SWGBarContracts", targets: ["SWGBarContracts"]),
        .library(name: "SWGBarStorage", targets: ["SWGBarStorage"]),
        .library(name: "SWGBarFilter", targets: ["SWGBarFilter"]),
        .library(name: "SWGBarAgent", targets: ["SWGBarAgent"]),
        .executable(name: "SWGBarApp", targets: ["SWGBarApp"]),
    ],
    targets: [
        .target(
            name: "SWGBarContracts",
            path: "Sources/SWGBarContracts"
        ),
        .target(
            name: "SWGBarStorage",
            dependencies: ["SWGBarContracts"],
            path: "Sources/SWGBarStorage",
            linkerSettings: [
                .linkedLibrary("sqlite3")
            ]
        ),
        .target(
            name: "SWGBarFilter",
            dependencies: ["SWGBarContracts"],
            path: "Sources/SWGBarFilter"
        ),
        .target(
            name: "SWGBarAgent",
            dependencies: ["SWGBarContracts", "SWGBarStorage", "SWGBarFilter"],
            path: "Sources/SWGBarAgent"
        ),
        .executableTarget(
            name: "SWGBarApp",
            dependencies: ["SWGBarContracts", "SWGBarAgent", "SWGBarStorage"],
            path: "Sources/SWGBarApp"
        ),
        .testTarget(
            name: "SWGBarTests",
            dependencies: ["SWGBarContracts", "SWGBarStorage", "SWGBarFilter", "SWGBarAgent"]
        ),
    ]
)
