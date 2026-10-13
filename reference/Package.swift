// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AidAdmin",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "aid-admin", targets: ["AidAdmin"]),
        .executable(name: "aid-admin-apply", targets: ["AidAdminApply"]),
        .executable(name: "aid-admin-bootstrap", targets: ["AidAdminBootstrap"]),
        .executable(name: "aid-admin-bootstrap-tests", targets: ["AidAdminBootstrapTests"]),
        .executable(name: "aid-admin-tests", targets: ["AidAdminTests"]),
        .library(name: "AidAdminCore", targets: ["AidAdminCore"]),
        .library(name: "AidAdminBootstrapCore", targets: ["AidAdminBootstrapCore"]),
    ],
    targets: [
        .target(name: "AidAdminCore"),
        .target(name: "AidAdminBootstrapCore"),
        .executableTarget(name: "AidAdmin", dependencies: ["AidAdminCore"]),
        .executableTarget(name: "AidAdminApply", dependencies: ["AidAdminCore"]),
        .executableTarget(name: "AidAdminBootstrap", dependencies: ["AidAdminBootstrapCore"]),
        .executableTarget(name: "AidAdminTests", dependencies: ["AidAdminCore"],
                          path: "tests/AidAdminCoreTests"),
        .executableTarget(name: "AidAdminBootstrapTests", dependencies: ["AidAdminBootstrapCore"],
                          path: "tests/AidAdminBootstrapTests"),
    ]
)
