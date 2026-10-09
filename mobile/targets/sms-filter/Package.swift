// swift-tools-version:5.9
// The scam-text filter's engine (the Swift twin of the Android message check)
// as a Swift package, so its parity tests run with `swift test` on a Mac and
// with xcodebuild on the iOS simulator. The app never links this package: the
// Expo plugin (mobile/plugins/withSmsFilter.js) compiles these same sources
// into the CleanwaySmsFilter extension target. docs/IOS.md §4.
import PackageDescription

let package = Package(
    name: "CleanwayMessageEngine",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "CleanwayMessageEngine", targets: ["CleanwayMessageEngine"]),
    ],
    targets: [
        .target(name: "CleanwayMessageEngine", path: "Sources/CleanwayMessageEngine"),
        .testTarget(
            name: "CleanwayMessageEngineTests",
            dependencies: ["CleanwayMessageEngine"],
            path: "Tests/CleanwayMessageEngineTests",
            exclude: ["Fixtures"]
        ),
    ]
)
