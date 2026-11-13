import Foundation

public enum VersionCompare {
    /// Compares dotted numeric versions (`"1.1" > "1.0.9" > "1.0"`, `"1.10" > "1.9"`).
    /// Pre-release and build suffixes (`-beta`, `+42`) are ignored.
    public static func isVersion(_ a: String, newerThan b: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            let core = s.split(whereSeparator: { $0 == "-" || $0 == "+" }).first.map(String.init) ?? s
            return core.split(separator: ".").map { Int($0.trimmingCharacters(in: .whitespaces)) ?? 0 }
        }
        let pa = parts(a), pb = parts(b)
        let n = max(pa.count, pb.count)
        for i in 0..<n {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    /// Returns true when `raw` starts with 1 to 4 numeric dot-separated segments and an optional `-pre` / `+build` suffix.
    public static func isValidVersionString(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 32 else { return false }
        return trimmed.range(of: #"^\d+(\.\d+){0,3}([+-][A-Za-z0-9._-]+)?$"#, options: .regularExpression) != nil
    }

    /// Formats a version string for display (`"1.0.0"` -> `"1.0"`, `"1.0.3"` -> `"1.0.3"`, `"3"` -> `"3.0"`, invalid -> `"1.0"`).
    public static func formattedDisplayVersion(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "1.0" }
        let numericPrefix = trimmed.split(whereSeparator: { $0 == "-" || $0 == "+" }).first.map(String.init) ?? trimmed
        let parts = numericPrefix.split(separator: ".", omittingEmptySubsequences: false)
        guard let majorSub = parts.first, let major = Int(majorSub), major >= 0 else { return "1.0" }
        let minor = (parts.count >= 2) ? (Int(parts[1]) ?? -1) : 0
        guard minor >= 0 else { return "1.0" }
        if parts.count >= 3, let patch = Int(parts[2]), patch > 0 {
            return "\(major).\(minor).\(patch)"
        }
        return "\(major).\(minor)"
    }
}
