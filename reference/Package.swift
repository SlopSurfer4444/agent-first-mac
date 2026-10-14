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
        .executable(name: "aid-admin-runtime-tests", targets: ["AidAdminRuntimeTests"]),
        .executable(name: "aid-admin-emergency-tests", targets: ["AidAdminEmergencyTests"]),
        .executable(name: "aid-admin-resume-launchd-tests", targets: ["AidAdminResumeLaunchdTests"]),
        .executable(name: "aid-admin-resume-home-manager-tests", targets: ["AidAdminResumeHomeManagerTests"]),
        .executable(name: "aid-admin-emergency-action", targets: ["AidAdminEmergencyAction"]),
        .library(name: "AidAdminCore", targets: ["AidAdminCore"]),
        .library(name: "AidAdminBootstrapCore", targets: ["AidAdminBootstrapCore"]),
    ],
    targets: [
        .target(name: "AidAdminRuntime"),
        .target(name: "AidAdminCore", dependencies: ["AidAdminRuntime"]),
        .target(name: "AidAdminBootstrapCore", dependencies: ["AidAdminRuntime", "AidAdminCore"]),
        .target(name: "AidAdminEmergencyCore", dependencies: ["AidAdminRuntime"]),
        .executableTarget(name: "AidAdminEmergencyAction", dependencies: ["AidAdminEmergencyCore", "AidAdminCore"]),
        .executableTarget(name: "AidAdminEmergencyTests", dependencies: ["AidAdminEmergencyCore"], path: "tests/AidAdminEmergencyTests"),
        .executableTarget(name: "AidAdminResumeLaunchdTests", dependencies: ["AidAdminCore"], path: "tests/AidAdminResumeLaunchdTests"),
        .executableTarget(name: "AidAdminResumeHomeManagerTests", dependencies: ["AidAdminCore"], path: "tests/AidAdminResumeHomeManagerTests"),
        .executableTarget(name: "AidAdminRuntimeTests", dependencies: ["AidAdminRuntime"], path: "tests/AidAdminRuntimeTests"),
        .executableTarget(name: "AidAdmin", dependencies: ["AidAdminCore"]),
        .executableTarget(name: "AidAdminApply", dependencies: ["AidAdminCore"]),
        .executableTarget(name: "AidAdminBootstrap", dependencies: ["AidAdminBootstrapCore"]),
        .executableTarget(name: "AidAdminTests", dependencies: ["AidAdminCore"],
                          path: "tests/AidAdminCoreTests"),
        .executableTarget(name: "AidAdminBootstrapTests", dependencies: ["AidAdminBootstrapCore"],
                          path: "tests/AidAdminBootstrapTests"),
    ]
)
