// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "ItemEncrypt",
    platforms: [
        .macOS(.v10_13), .iOS(.v11), .tvOS(.v11), .watchOS(.v5)
    ],
    products: [
        .library(
            name: "ItemEncrypt",
            targets: ["ItemEncrypt"]
        ),
    ],
    dependencies: [
        // IDZSwiftCommonCrypto
        .package(url: "git@github.com:AverageHelper/IDZSwiftCommonCrypto.git", .upToNextMinor(from: "0.13.2")),
    ],
    targets: [
        .target(
            name: "ItemEncrypt",
            dependencies: ["IDZSwiftCommonCrypto"],
            path: "ItemEncrypt/Sources",
            exclude: ["EncryptionEncoder-JSON.swift"]
        ),
        .testTarget(
            name: "ItemEncryptTests",
            dependencies: ["ItemEncrypt"],
            path: "ItemEncryptTests/Sources",
            exclude: ["EncryptingMacOSTypes.swift", "EncryptingiOSTypes.swift"]
        ),
    ]
)
