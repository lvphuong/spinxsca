# Spinx SecureCode AI — desktop app

Tauri 2 + React. App chạy dịch vụ spinxsca cục bộ làm sidecar (`serve --desktop`, chỉ loopback,
token theo mỗi lần mở) — xem ADR-048.

## Phát triển

```sh
pnpm build                                   # build CLI
SPINXSCA_SIDECAR="node $PWD/apps/cli/dist/index.mjs" pnpm --filter @spinxsca/desktop tauri dev
```

## Đóng gói bản phát hành

Cả hai script đều: build CLI → stage sidecar cho đúng target (`scripts/stage-sidecar.mjs`: Node.js
chính thức đã kiểm SHA256, `node_modules` production phẳng, chỉ giữ binary native của target, có smoke
test khi target trùng máy build) → `tauri build`. Kết quả nằm trong
`apps/desktop/release/<version>/<os>-<arch>/` kèm `SHA256SUMS` và `sidecar-manifest.json`.

### macOS — build, ký, notarize

Cần Xcode Command Line Tools, Rust (`rustup`), Node.js theo `.nvmrc`, pnpm.

```sh
# Bản thử, chưa ký (chữ ký ad-hoc)
pnpm --filter @spinxsca/desktop release:mac --unsigned

# Bản phát hành: ký bằng Developer ID + notarize bằng keychain profile
xcrun notarytool store-credentials spinxsca-notary \
  --apple-id you@example.com --team-id TEAMID --password <app-specific-password>   # một lần
apps/desktop/scripts/build-macos.sh --arch arm64 --notary-profile spinxsca-notary
apps/desktop/scripts/build-macos.sh --arch x64   --notary-profile spinxsca-notary
```

| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--arch arm64\|x64` | Kiến trúc đích (mặc định: máy hiện tại; build x64 được trên máy Apple Silicon) |
| `--identity "Developer ID Application: …"` | Danh tính ký; mặc định `$APPLE_SIGNING_IDENTITY`, hoặc danh tính Developer ID duy nhất trong keychain |
| `--notary-profile NAME` | Keychain profile của `notarytool` (hoặc `$SPINXSCA_NOTARY_PROFILE`) |
| `--no-notarize` | Ký nhưng không notarize |
| `--unsigned` | Chỉ ký ad-hoc, không notarize |
| `--skip-build` | Dùng lại `.app` đã build, chỉ ký/đóng gói lại |

Thứ tự ký: mọi Mach-O lồng trong `Contents/Resources` (Node runtime với
`src-tauri/entitlements/sidecar-node.plist` — JIT của V8; các addon `.node`; esbuild) → binary chính →
bundle, đều có hardened runtime + timestamp. Sau đó notarize + staple `.app`, tạo DMG, ký + notarize
+ staple DMG và kiểm bằng `spctl`.

Biến môi trường thay cho tham số (dùng cho CI):

- `APPLE_CERTIFICATE` (p12 base64) + `APPLE_CERTIFICATE_PASSWORD` — nạp vào keychain tạm, tự xoá khi xong
- Notarize bằng API key: `APPLE_API_KEY_PATH` (.p8) + `APPLE_API_KEY` (key id) + `APPLE_API_ISSUER`
- Notarize bằng Apple ID: `APPLE_ID` + `APPLE_PASSWORD` (app-specific) + `APPLE_TEAM_ID`
- `TAURI_SIGNING_PRIVATE_KEY` (+ `_PASSWORD`) — thêm gói updater `.app.tar.gz` + `.sig`

### Windows — build (chưa ký)

Cần Visual Studio C++ Build Tools, Rust (`rustup`, toolchain MSVC), Node.js theo `.nvmrc`, pnpm.
Tauri tự tải NSIS và WiX lần đầu.

```powershell
pnpm --filter @spinxsca/desktop release:win
# hoặc
powershell -NoProfile -ExecutionPolicy Bypass -File apps\desktop\scripts\build-windows.ps1 [-Bundles nsis] [-SkipBuild]
```

Tạo `Spinx-SecureCode-AI_<version>_x64-setup.exe` (NSIS, cài cho người dùng hiện tại) và `.msi`.
Có `TAURI_SIGNING_PRIVATE_KEY` thì kèm `.sig` cho updater. Chưa có Authenticode nên SmartScreen sẽ
cảnh báo lần chạy đầu; khi có chứng chỉ, cấu hình `bundle.windows.signCommand` trong `tauri.conf.json`.

### Updater

`scripts/latest-json.mjs <version> <base URL> <thư mục chứa gói>` tạo `latest.json` từ các file
`.sig`. Plugin updater chỉ bật khi `plugins.updater.pubkey` trong `tauri.conf.json` đã được thay
bằng public key thật (`pnpm tauri signer generate`).
