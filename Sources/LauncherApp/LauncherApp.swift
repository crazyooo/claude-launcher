import SwiftUI
import LauncherCore

@main struct LauncherApp: App {
    @StateObject private var model = EnvironmentModel()
    var body: some Scene {
        Window("Claude 环境检测", id: "main") {
            DetectorConsole(model: model)
        }
        .defaultSize(width: 1180, height: 800)
        .commands {
            CommandGroup(replacing: .appSettings) {
                DetectorSettingsCommand()
            }
        }
        Window("设置", id: "settings") {
            DetectorAppSettings(model: model)
        }
        .windowResizability(.contentSize)
        MenuBarExtra {
            DetectorMenu(model: model)
        } label: {
            DetectorMenuBarLabel(model: model, preferences: model.preferences)
        }
        .menuBarExtraStyle(.window)
    }
}

private struct DetectorSettingsCommand: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Button("设置…") {
            openWindow(id: "settings")
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut(",", modifiers: .command)
    }
}
