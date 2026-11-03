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
            // After learning, add or take away capabilities: profiles and file kinds first, then
            // rule by rule in the table. These switches save on their own.
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
            .frame(minHeight: 220)
            if dirty {
                Text("Unsaved changes. Save writes a backup of the previous config first.")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
        .padding()
        .sheet(isPresented: Binding(get: { store.addingPermission },
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

/// "Add Permission…": everything you can grant or take away after learning, in one native
/// grouped form. Every change saves right away (with a backup) and applies on the next run.
struct AddPermissionSheet: View {
    let store: AppStore
    let key: String

    var body: some View {
        let entry = store.entries.first { $0.id == key }
        VStack(spacing: 0) {
            if let entry {
                form(entry)
            }
            HStack {
                Text("Changes save right away and apply the next time the app runs. Protected locations stay blocked.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 12)
                Button("Done") { store.addingPermission = false }.keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20).padding(.vertical, 12)
        }
        .frame(width: 520, height: 600)
    }

    func form(_ entry: AppEntry) -> some View {
        let active = Set(entry.config.profiles ?? [])
        let yours = entry.config.rules.filter { $0.source == .custom }
        let kinds = Set(yours.compactMap(\.label))
        let others = yours.filter { $0.label == nil }
        let value = store.newValue.trimmingCharacters(in: .whitespaces)
        return Form {
            Section("Profiles") {
                ForEach(Profile.allCases, id: \.self) { profile in
                    Toggle(isOn: Binding(get: { active.contains(profile) },
                                         set: { store.applyProfile(entry.id, profile, on: $0) })) {
                        Text(profile.title)
                        Text(profile.explanation)
                    }
                }
            }
            Section("Read anywhere") {
                ForEach(FileCategory.allCases, id: \.self) { category in
                    Toggle(category.title, isOn: Binding(get: { kinds.contains(category.rawValue) },
                                                         set: { store.applyCategory(entry.id, category, on: $0) }))
                        .help(category.extensions.map { ".\($0)" }.joined(separator: " "))
                }
            }
            Section {
                ForEach(others) { rule in
                    HStack {
                        Text(RuleText.describe(rule)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button { store.removeRuleNow(entry.id, ruleID: rule.id) } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless).help("Remove")
                    }
                }
                HStack {
                    Picker("", selection: Bindable(store).newAccess) {
                        ForEach(CustomAccess.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .labelsHidden().fixedSize()
                    TextField("", text: Bindable(store).newValue, prompt: Text("mp4, mkv — or a folder"))
                        .labelsHidden()
                        .onSubmit { if !value.isEmpty { store.addRuleNow(entry.id) } }
                    Button("Choose…") { store.chooseFolder() }
                    Button("Add") { store.addRuleNow(entry.id) }.disabled(value.isEmpty)
                }
            } header: {
                Text("Other files and folders")
            } footer: {
                Text("File types count anywhere; a folder covers everything inside it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Limits") {
                LabeledContent("CPU seconds") {
                    LimitField(label: "none", value: entry.config.limits?.cpuSeconds) { store.applyLimit(entry.id, \.cpuSeconds, $0) }
                }
                LabeledContent("Memory MiB") {
                    LimitField(label: "none", value: entry.config.limits?.memoryMB) { store.applyLimit(entry.id, \.memoryMB, $0) }
                }
            }
        }
        .formStyle(.grouped)
    }
}
