import UniformTypeIdentifiers

/// File categories as macOS sections them (Finder's "Kind"), for broad permissions like
/// "read all media". Membership is decided by macOS's own type system (UTType conformance) when
/// the rule is added; the resulting extension list is stored in the config, so it stays auditable.
public enum FileCategory: String, CaseIterable, Sendable {
    case media
    case images
    case documents

    public var title: String {
        switch self {
        case .media: return "Media (video & audio)"
        case .images: return "Images"
        case .documents: return "Documents"
        }
    }

    /// "media files (video & audio)", for sentences like "Read all …".
    public var noun: String {
        switch self {
        case .media: return "media files (video & audio)"
        case .images: return "image files"
        case .documents: return "document files"
        }
    }

    /// Candidate extensions; each is kept only if macOS classifies it into this category.
    /// Left out on purpose although macOS files them here: `.ts` (also TypeScript source) and
    /// `.key` (also private keys). Add them explicitly if you really need them.
    static let candidates: [FileCategory: [String]] = [
        .media: """
            mp4 m4v mov avi mkv wmv flv webm mpg mpeg m2ts mts 3gp ogv vob divx
            mp3 m4a m4b aac wav aiff aif flac ogg oga opus wma mid midi caf amr ac3
            """.split(whereSeparator: \.isWhitespace).map(String.init),
        .images: "jpg jpeg png gif heic heif tif tiff bmp webp raw cr2 nef arw dng ico psd"
            .split(separator: " ").map(String.init),
        .documents: "pdf doc docx odt pages rtf txt md csv xls xlsx ods numbers ppt pptx odp epub"
            .split(separator: " ").map(String.init),
    ]

    /// The extensions macOS puts in this category on this Mac.
    public var extensions: [String] {
        (Self.candidates[self] ?? []).filter { ext in
            guard let type = UTType(filenameExtension: ext), !type.isDynamic else { return false }
            switch self {
            case .media:
                return type.conforms(to: .movie) || type.conforms(to: .audio)
            case .images:
                return type.conforms(to: .image)
            case .documents:
                // Office/iWork/PDF/ePub documents, plus plain and rich text, but never code,
                // scripts or data formats (json, yaml, …), which is where secrets tend to live.
                if type.conforms(to: .sourceCode) || type.conforms(to: .script) { return false }
                return type.conforms(to: .compositeContent) || type.conforms(to: .plainText)
                    || type.conforms(to: .rtf) || type.conforms(to: .commaSeparatedText)
            }
        }
    }
}
