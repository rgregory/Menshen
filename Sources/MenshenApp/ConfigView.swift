import MenshenCore
import SwiftUI

struct ConfigView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        if item.entry == nil {
            ContentUnavailableView("Not learned yet", systemImage: "doc.badge.gearshape",
                                   description: Text("Learn the app first to create its config."))
        } else {
            content
        }
    }

    var content: some View {
        let key = item.id
        let dirty = store.isDirty(key)
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Picker("Show", selection: Bindable(store).ruleFilter) {
                    ForEach(RuleFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .frame(width: 200)
                TextField("Search rules", text: Bindable(store).ruleSearch)
                Button("Add Permission…") { store.permissionAppliesNow = false; store.addingPermission = true }
                Button("Sandbox Rules") { store.showSandboxRules(key) }
                    .fixedSize()
                    .help("Regenerate the full sandbox profile from the current config and show it")
                Button("Revert") { store.revert(key) }.disabled(!dirty)
                Button("Save") { store.save(key) }.disabled(!dirty).keyboardShortcut("s")
            }
            logging(key)
            Table(store.rules(key)) {
                TableColumn("Allow") { rule in
                    Toggle("", isOn: Binding(get: { rule.action == .allow },
                                             set: { store.setAction(key, ruleID: rule.id, allow: $0) }))
                        .labelsHidden()
                }
                .width(40)
                TableColumn("What") { rule in
                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        if rule.flagged == true { Image(systemName: "flag.fill").foregroundStyle(.orange) }
                        Text(RuleText.describe(rule)).lineLimit(2)
                    }
                    .help("\(rule.id): \(rule.operations.joined(separator: " ")) \(rule.filter.kind.rawValue) \(rule.filter.value ?? "")")
                }
                .width(min: 240, ideal: 380)
                TableColumn("Access") { rule in AccessBadge(text: RuleText.access(rule.operations)) }
                    .width(min: 80, ideal: 90)
                TableColumn("Source") { rule in
                    Text(rule.source == .hardening ? "protection" : rule.source == .custom ? "yours" : "learned").font(.caption).foregroundStyle(.secondary)
                }
                .width(min: 60, ideal: 70)
                TableColumn("Seen") { rule in Text(rule.seen > 0 ? "\(rule.seen)" : "").monospacedDigit() }
                    .width(min: 35, ideal: 45)
                TableColumn("Note") { rule in
                    Text(note(rule)).font(.caption).foregroundStyle(.secondary).lineLimit(2).help(rule.note ?? "")
                }
                .width(min: 120, ideal: 220)
                TableColumn("") { rule in
                    if rule.source == .custom {
                        Button { store.removeCustom(key, ruleID: rule.id) } label: { Image(systemName: "trash") }
                            .buttonStyle(.borderless)
                            .help("Remove this rule of yours")
                    }
                }
                .width(28)
            }
            if dirty {
                Text("Unsaved changes. Save writes a backup of the previous config first.")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
        .padding()
        .sheet(isPresented: Binding(get: { store.addingPermission && !store.permissionAppliesNow },
                                    set: { if !$0 { store.addingPermission = false } })) { AddPermissionSheet(store: store, key: key) }
        .sheet(isPresented: Binding(get: { store.sbplText != nil }, set: { if !$0 { store.sbplText = nil } })) {
            VStack(alignment: .leading) {
                Text("Sandbox rules (SBPL), as compiled for the kernel").font(.headline)
                ScrollView {
                    Text(store.sbplText ?? "")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack {
                    Spacer()
                    Button("Close") { store.sbplText = nil }.keyboardShortcut(.defaultAction)
                }
            }
            .padding()
            .frame(width: 820, height: 560)
        }
    }

    func logging(_ key: String) -> some View {
        HStack(spacing: 14) {
            Text("Log:").foregroundStyle(.secondary)
            toggle(key, "Blocked", \.denials)
            toggle(key, "Network", \.network)
            toggle(key, "Launches", \.exec)
            toggle(key, "Outside writes", \.writeOutside)
                .help("Writes outside the app's own folders")
        }
    }

    /// The first sentence of a rule's note, or what gets logged for it.
    func note(_ rule: Rule) -> String {
        if let note = rule.note {
            return note.replacingOccurrences(of: "Not seen during learning.", with: "").trimmingCharacters(in: .whitespaces)
        }
        return rule.category.map { "logged (\($0.rawValue))" } ?? ""
    }

    func toggle(_ key: String, _ title: String, _ path: WritableKeyPath<LoggingSettings, Bool>) -> some View {
        Toggle(title, isOn: Binding(
            get: { store.drafts[key]?.logging[keyPath: path] ?? true },
            set: { store.drafts[key]?.logging[keyPath: path] = $0 }))
    }
}

/// "Add Permission…": a broad rule of your own — file types anywhere, or a folder.
struct AddPermissionSheet: View {
    let store: AppStore
    let key: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add a permission").font(.headline)
            Picker("Allow", selection: Bindable(store).newAccess) {
                ForEach(CustomAccess.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            Picker("For", selection: Bindable(store).newKind) {
                ForEach(PermissionKind.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            switch store.newKind {
            case .category:
                Picker("Category", selection: Bindable(store).newCategory) {
                    ForEach(FileCategory.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                // Show exactly what the category covers, as macOS classifies types on this Mac.
                Text(store.newCategory.extensions.map { ".\($0)" }.joined(separator: " "))
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if store.newCategory == .documents {
                    Text("Code, scripts and config files (json, yaml, sh…) are left out on purpose: that's where keys and tokens live.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            case .fileTypes:
                TextField("e.g. mp4, mkv, mov", text: Bindable(store).newValue)
                Text("Every file with these extensions, anywhere.")
                    .font(.caption).foregroundStyle(.secondary)
            case .folder:
                HStack {
                    TextField("Folder", text: Bindable(store).newValue)
                    Button("Choose…") { store.chooseFolder() }
                }
                Text("Everything inside this folder.").font(.caption).foregroundStyle(.secondary)
            }
            Text("Protected locations (like ~/.ssh and other apps' data) stay blocked either way. Save the config to apply.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { store.addingPermission = false }.keyboardShortcut(.cancelAction)
                Button("Add") { store.addPermission(key) }.keyboardShortcut(.defaultAction)
                    .disabled(store.newKind != .category && store.newValue.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding()
        .frame(width: 440)
    }
}
