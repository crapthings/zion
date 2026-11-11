import SwiftUI

/// Shared spacing keeps control gaps, section padding, and page insets on one scale.
enum InterfaceSpacing {
    static let small: CGFloat = 8
    static let medium: CGFloat = 16
    static let large: CGFloat = 32
}

/// Search fields use a quiet filled surface without an outline.
struct WorkspaceSearchStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .textFieldStyle(.plain)
            .padding(InterfaceSpacing.small)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Empty workspaces keep their message at the leading edge instead of centering the page.
struct WorkspaceEmptyState: View {
    let title: String
    let symbol: String

    var body: some View {
        Label(title, systemImage: symbol)
            .foregroundStyle(.secondary)
            .padding(InterfaceSpacing.large)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// A borderless menu retains native picker selection and checkmarks without a control bezel.
struct WorkspacePicker<Value: Hashable, Options: View>: View {
    let title: String
    let selectionTitle: String
    @Binding var selection: Value
    @ViewBuilder let options: Options

    var body: some View {
        Menu {
            Picker(title, selection: $selection) { options }
        } label: {
            Text(selectionTitle).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
        }
        .menuStyle(.borderlessButton)
        .accessibilityLabel(title)
    }
}
