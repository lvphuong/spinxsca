# Spinx SecureCode AI — desktop app

Ứng dụng desktop của spinxsca (Tauri 2 + React 19). App chạy dịch vụ spinxsca ngay trên máy làm
*sidecar* (`spinxsca serve --desktop`). Vì vậy bạn quét, rà soát và phê duyệt các hành động của
agent mà không cần dựng server. Mã nguồn không rời máy, trừ phần gửi cho LLM provider bạn cấu hình.
Quyết định thiết kế nằm ở [ADR-048](../../docs/adr/ADR-048-desktop-tauri.md).

> Trạng thái: phiên bản 0.5.x, **chưa ký**. macOS sẽ hỏi lại ở lần mở đầu tiên, Windows SmartScreen
> sẽ cảnh báo. Pipeline ký, notarize và updater đã viết sẵn, chỉ chờ chứng chỉ.

## Tính năng

| Màn hình | Việc |
|---|---|
| **Onboarding** | Kiểm tra Docker, chọn LLM provider và lưu API key vào keychain của hệ điều hành, chọn thư mục dự án đầu tiên |
| **Projects** | Danh sách dự án, chạy scan hoặc review, xem trạng thái job |
| **Review** | Case rà soát tự chủ gồm objectives, work items, findings và verdict, journal, coverage, báo cáo case; cập nhật trực tiếp qua SSE |
| **Inbox** | Các hành động agent đang chờ người quyết định: thẻ phê duyệt có diff thật và nhãn *human-only*, chọn grant `once`/`case`/`standing` |
| **Settings** | Provider và model, xoá key, mức AI, ngân sách, trạng thái sidecar và Docker |

App dùng chung engine với CLI, nên mọi thứ trong [README gốc](../../README.md) đều áp dụng: scanner
trong container không mạng, policy engine L0–L12, audit có hash-chain, PoC L3 trong sandbox, phân tích
logic recon-first (Phase 6).

## Yêu cầu khi chạy

- macOS 12 trở lên, Windows 10/11 x64 hoặc Linux có WebKitGTK 4.1.
- Docker Desktop hoặc Docker Engine đang chạy, để chạy scanner và sandbox. App phát hiện Docker qua
  `PATH` của login shell, nên Docker cài bằng Homebrew hoặc OrbStack vẫn được nhận.
- Chỉ cần API key khi dùng AI. Có thể dùng Claude hoặc một endpoint tương thích OpenAI chạy nội bộ.

Bản phát hành đã đóng kèm Node.js runtime và CLI, nên máy người dùng không cần cài Node hay pnpm.

## Kiến trúc

```
┌──────────────── Tauri shell (Rust, src-tauri/) ────────────────┐
│ single-instance · tray · supervisor · keychain · login-shell PATH │
│      │ spawn: node sidecar/cli serve --desktop --port 0           │
│      │ env: SPINXSCA_DESKTOP_TOKEN (256-bit, chỉ trong RAM)        │
│      ▼                                                            │
│  sidecar ── "SPINXSCA_READY port=…" ──► supervisor                │
│  (Hono API /v1 + SSE, chỉ 127.0.0.1)                              │
│      ▲                                                            │
│      │ fetch + Bearer token (initialization script đã đóng băng)  │
│  Webview (React, src/) ── CSP chặt, withGlobalTauri: false        │
└───────────────────────────────────────────────────────────────────┘
```

| Thư mục | Nội dung |
|---|---|
| `src-tauri/src/lib.rs` | Dựng app: plugin (single-instance đăng ký đầu tiên), tray, đóng cửa sổ thì thu vào tray, các command của app |
| `src-tauri/src/supervisor.rs` | Khởi động sidecar, đọc handshake, health check, tự khởi động lại có backoff (tối đa 5 lần, giữ nguyên cổng), xoay log |
| `src-tauri/src/token.rs` | Sinh launch token cho mỗi lần mở app |
| `src-tauri/src/secrets.rs` | Key của provider trong keychain (macOS Keychain, Windows Credential Manager, Secret Service) |
| `src-tauri/src/shell_env.rs` | Lấy `PATH` từ login shell, để app mở từ Finder vẫn thấy `docker` |
| `src/api/` | Client `/v1` và các kiểu dữ liệu |
| `src/views/`, `src/components/` | Các màn hình, thẻ phê duyệt, diff, Markdown không HTML thô, iframe báo cáo |
| `src/lib/` | SSE, diff, định dạng hiển thị, cầu nối tới shell |
| `scripts/` | Stage sidecar, tải Node chính thức, build macOS và Windows, tạo `latest.json` |

Webview chỉ gọi được năm command của app: `docker_status`, `sidecar_status`, `provider_key_present`,
`set_provider_key`, `delete_provider_key`. Webview chỉ ghi, xoá hoặc hỏi key có tồn tại hay không.
Webview **không bao giờ đọc được key**: Rust chuyển key vào môi trường của sidecar.

## Mô hình bảo mật

- **Server chỉ nghe trên loopback.** Launch token đổi mỗi lần mở app và có quyền local-owner. Server
  chặn Host không phải loopback (chống DNS rebinding) và Origin ngoài danh sách của app.
- **Webview:** CSP thật, xem `tauri.conf.json` (`connect-src` chỉ gồm `self`, IPC và `127.0.0.1`,
  `object-src 'none'`, `form-action 'none'`), `freezePrototype`, capability tối thiểu trong
  `src-tauri/capabilities/default.json`. Opener chỉ mở `https://`. Hộp thoại chỉ cho chọn thư mục.
- **Báo cáo** được hiển thị trong iframe `sandbox=""`, kèm CSP chặn mạng. Markdown hiển thị không có
  HTML thô.
- **Phê duyệt:** yêu cầu human-only chỉ được duyệt một lần. Người trả lời đầu tiên thắng, kể cả khi
  CLI hoặc server cùng trả lời một approval.
- **Sidecar tự thoát** khi tiến trình cha chết. Không có cổng nào bị bỏ lại.

## Phát triển

Cần Rust (`rustup`), Node.js theo `.nvmrc`, pnpm. Linux cần thêm
`libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libsecret-1-dev`.

```sh
pnpm install
pnpm build                                     # build CLI ở gốc repo
SPINXSCA_SIDECAR="node $PWD/apps/cli/dist/index.mjs" pnpm --filter @spinxsca/desktop tauri dev
```

`SPINXSCA_SIDECAR` trỏ tới CLI vừa build, nên không cần stage sidecar khi phát triển. Vite phục vụ UI ở
`http://localhost:1420` và hỗ trợ hot reload. Sửa mã Rust thì Tauri tự build lại.

Chỉ làm UI mà không cần shell:

```sh
pnpm --filter @spinxsca/desktop dev            # UI trong trình duyệt; cần một server spinxsca để gọi /v1
```

## Kiểm thử

```sh
pnpm --filter @spinxsca/desktop typecheck
pnpm --filter @spinxsca/desktop test           # Vitest + jsdom: component, diff, định dạng
pnpm --filter @spinxsca/desktop e2e            # Playwright với /v1 và SSE giả
cd apps/desktop/src-tauri && cargo test        # token, handshake, backoff, keychain
```

CI (`.github/workflows/ci.yml`) chạy typecheck và test. `tauri build` đầy đủ chạy trong
`desktop-release.yml`.

> Biome ở gốc repo chỉ lint `**/*.ts`. Các file `.tsx` của app chỉ được kiểm bằng `tsc` và test, nên
> khi sửa chúng cần chạy `typecheck` và `e2e`.

## Đóng gói bản phát hành

Cả hai script làm theo cùng thứ tự. Bước một: build CLI. Bước hai: stage sidecar cho đúng target bằng
`scripts/stage-sidecar.mjs`, gồm Node.js chính thức đã kiểm SHA256, `node_modules` production phẳng,
chỉ giữ binary native của target, và smoke test khi target trùng máy build. Bước ba: `tauri build`.
Kết quả nằm trong `apps/desktop/release/<version>/<os>-<arch>/`, kèm `SHA256SUMS` và
`sidecar-manifest.json`.

### macOS — build, ký, notarize

Cần Xcode Command Line Tools, Rust, Node.js theo `.nvmrc`, pnpm.

```sh
# Bản thử, chưa ký (chữ ký ad-hoc)
pnpm --filter @spinxsca/desktop release:mac --unsigned

# Bản phát hành: ký bằng Developer ID và notarize bằng keychain profile
xcrun notarytool store-credentials spinxsca-notary \
  --apple-id you@example.com --team-id TEAMID --password <app-specific-password>   # một lần
apps/desktop/scripts/build-macos.sh --arch arm64 --notary-profile spinxsca-notary
apps/desktop/scripts/build-macos.sh --arch x64   --notary-profile spinxsca-notary
```

| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--arch arm64\|x64` | Kiến trúc đích; mặc định là máy hiện tại. Build x64 được trên máy Apple Silicon |
| `--identity "Developer ID Application: …"` | Danh tính ký; mặc định là `$APPLE_SIGNING_IDENTITY` hoặc danh tính Developer ID duy nhất trong keychain |
| `--notary-profile NAME` | Keychain profile của `notarytool`, hoặc `$SPINXSCA_NOTARY_PROFILE` |
| `--no-notarize` | Ký nhưng không notarize |
| `--unsigned` | Chỉ ký ad-hoc, không notarize |
| `--skip-build` | Dùng lại `.app` đã build, chỉ ký và đóng gói lại |

Thứ tự ký bắt đầu từ mọi Mach-O lồng trong `Contents/Resources`: Node runtime (với entitlement JIT của
V8 trong `src-tauri/entitlements/sidecar-node.plist`), các addon `.node` và esbuild. Tiếp theo là binary
chính, rồi bundle. Mọi bước đều có hardened runtime và timestamp. Sau đó script notarize và staple
`.app`, tạo DMG, ký, notarize và staple DMG, rồi kiểm bằng `spctl`.

Biến môi trường thay cho tham số, dùng cho CI:

- `APPLE_CERTIFICATE` (p12 base64) và `APPLE_CERTIFICATE_PASSWORD`: nạp vào keychain tạm, tự xoá khi xong.
- Notarize bằng API key: `APPLE_API_KEY_PATH` (.p8), `APPLE_API_KEY` (key id), `APPLE_API_ISSUER`.
- Notarize bằng Apple ID: `APPLE_ID`, `APPLE_PASSWORD` (app-specific), `APPLE_TEAM_ID`.
- `TAURI_SIGNING_PRIVATE_KEY` (và `_PASSWORD`): thêm gói updater `.app.tar.gz` và `.sig`.

### Windows — build (chưa ký)

Cần Visual Studio C++ Build Tools, Rust với toolchain MSVC, Node.js theo `.nvmrc`, pnpm. Tauri tự tải
NSIS và WiX ở lần đầu.

```powershell
pnpm --filter @spinxsca/desktop release:win
# hoặc
powershell -NoProfile -ExecutionPolicy Bypass -File apps\desktop\scripts\build-windows.ps1 [-Bundles nsis] [-SkipBuild]
```

Script tạo `Spinx-SecureCode-AI_<version>_x64-setup.exe` (NSIS, cài cho người dùng hiện tại) và `.msi`.
Nếu có `TAURI_SIGNING_PRIVATE_KEY`, script kèm `.sig` cho updater. Chưa có Authenticode nên SmartScreen
sẽ cảnh báo ở lần chạy đầu. Khi có chứng chỉ, cấu hình `bundle.windows.signCommand` trong
`tauri.conf.json`.

### Linux và CI

`desktop-release.yml` build macOS (arm64, x64), Windows và Linux (`.deb`, AppImage). Bước ký và
updater chỉ chạy khi các secret tương ứng có mặt.

### Updater

`scripts/latest-json.mjs <version> <base URL> <thư mục chứa gói>` tạo `latest.json` từ các file `.sig`.
Plugin updater chỉ bật khi `plugins.updater.pubkey` trong `tauri.conf.json` đã được thay bằng public
key thật, tạo bằng `pnpm tauri signer generate`.

## Xử lý sự cố

| Triệu chứng | Cách xử lý |
|---|---|
| macOS báo app "không xác định được nhà phát triển" | Bản chưa ký: chuột phải vào app, chọn **Open**, hoặc chạy `xattr -dr com.apple.quarantine "/Applications/Spinx SecureCode AI.app"` |
| Onboarding báo không thấy Docker | Mở Docker Desktop (`open -a Docker`) rồi bấm kiểm tra lại. App lấy `PATH` từ login shell, nên `docker` phải chạy được trong terminal |
| Sidecar khởi động lại liên tục rồi dừng | Xem log sidecar trong thư mục log của app; trạng thái sidecar có trong **Settings**. Thường do cổng bị chặn hoặc bản stage thiếu binary native của target |
| AI báo thiếu credential | Lưu lại key trong **Settings**. Key nằm trong keychain, không nằm trong thư mục `.spinxsca` |
| Approval đã được trả lời ở nơi khác | Bình thường: người trả lời đầu tiên thắng. Inbox sẽ tự làm mới |
