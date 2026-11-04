#!/usr/bin/env bash
# Builds, signs and notarizes the macOS desktop app (ADR-048).
#
#   apps/desktop/scripts/build-macos.sh [--arch arm64|x64] [--identity "Developer ID Application: …"]
#                                       [--notary-profile NAME] [--no-notarize] [--unsigned] [--skip-build]
#
# Steps: build the CLI → stage the sidecar for the target (official Node.js, flat node_modules) →
# `tauri build --bundles app --no-sign` → sign every Mach-O inside the app inside-out with the
# hardened runtime and a secure timestamp (the Node runtime gets entitlements/sidecar-node.plist) →
# notarize and staple the app → DMG → sign, notarize and staple the DMG → Gatekeeper check →
# optional updater archive (.app.tar.gz + minisign .sig) → SHA256SUMS.
# Output: apps/desktop/release/<version>/macos-<arch>/
#
# Signing identity: --identity, else $APPLE_SIGNING_IDENTITY, else the only "Developer ID Application"
# identity in the keychain. CI: $APPLE_CERTIFICATE (base64 .p12) and $APPLE_CERTIFICATE_PASSWORD are
# imported into a temporary keychain that is deleted on exit.
#
# Notarization credentials, first match wins:
#   --notary-profile NAME / $SPINXSCA_NOTARY_PROFILE   keychain profile from `xcrun notarytool store-credentials`
#   $APPLE_API_KEY_PATH + $APPLE_API_KEY + $APPLE_API_ISSUER   App Store Connect API key (.p8, key id, issuer)
#   $APPLE_ID + $APPLE_PASSWORD + $APPLE_TEAM_ID       Apple ID with an app-specific password
#
# Updater archive: when $TAURI_SIGNING_PRIVATE_KEY (and $TAURI_SIGNING_PRIVATE_KEY_PASSWORD) is set.
# --unsigned: ad-hoc signature only, no notarization (local testing; Gatekeeper will warn).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop="$(cd "$here/.." && pwd)"
repo="$(cd "$desktop/../.." && pwd)"
tauri_dir="$desktop/src-tauri"
entitlements="$tauri_dir/entitlements/sidecar-node.plist"

arch="$(uname -m)"
identity="${APPLE_SIGNING_IDENTITY:-}"
notary_profile="${SPINXSCA_NOTARY_PROFILE:-}"
notarize=1
unsigned=0
skip_build=0

die() { echo "build-macos: $*" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch="${2:?--arch needs a value}"; shift 2 ;;
    --identity) identity="${2:?--identity needs a value}"; shift 2 ;;
    --notary-profile) notary_profile="${2:?--notary-profile needs a value}"; shift 2 ;;
    --no-notarize) notarize=0; shift ;;
    --unsigned) unsigned=1; notarize=0; shift ;;
    --skip-build) skip_build=1; shift ;;
    --) shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

case "$arch" in
  arm64|aarch64) arch=arm64; triple=aarch64-apple-darwin; label=aarch64 ;;
  x64|x86_64) arch=x64; triple=x86_64-apple-darwin; label=x64 ;;
  *) die "unsupported --arch $arch (arm64 or x64)" ;;
esac

[ "$(uname -s)" = Darwin ] || die "run this on macOS"
for tool in node pnpm cargo rustup codesign xcrun hdiutil ditto shasum; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
[ -d "$repo/node_modules" ] || die "dependencies are missing: run pnpm install --frozen-lockfile"

work="$(mktemp -d "${TMPDIR:-/tmp}/spinxsca-macos.XXXXXX")"
keychain=""
saved_keychains=""
cleanup() {
  if [ -n "$keychain" ]; then
    # Restore the user's keychain search list before deleting the temporary keychain.
    if [ -n "$saved_keychains" ]; then
      # shellcheck disable=SC2086
      eval security list-keychains -d user -s $saved_keychains || true
    fi
    security delete-keychain "$keychain" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# --- signing identity -----------------------------------------------------------------------------
if [ "$unsigned" = 1 ]; then
  identity="-"
else
  if [ -n "${APPLE_CERTIFICATE:-}" ]; then
    step "Importing the signing certificate into a temporary keychain"
    keychain="$work/signing.keychain-db"
    kc_pass="$(openssl rand -hex 24)"
    security create-keychain -p "$kc_pass" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$kc_pass" "$keychain"
    printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$work/cert.p12"
    security import "$work/cert.p12" -k "$keychain" -P "${APPLE_CERTIFICATE_PASSWORD:-}" -T /usr/bin/codesign >/dev/null
    rm -f "$work/cert.p12"
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kc_pass" "$keychain" >/dev/null
    saved_keychains="$(security list-keychains -d user | tr '\n' ' ')"
    # shellcheck disable=SC2086
    eval security list-keychains -d user -s "\"$keychain\"" $saved_keychains
  fi
  if [ -z "$identity" ]; then
    ids="$(security find-identity -v -p codesigning ${keychain:+"$keychain"} | sed -n 's/.*"\(Developer ID Application: .*\)"$/\1/p' | sort -u)"
    count="$(printf '%s' "$ids" | grep -c . || true)"
    [ "$count" = 1 ] || die "found $count \"Developer ID Application\" identities; pass --identity (or --unsigned)${ids:+:
$ids}"
    identity="$ids"
  fi
  echo "signing as: $identity"
fi

# --- notarization credentials ---------------------------------------------------------------------
notary_args=()
if [ "$notarize" = 1 ]; then
  if [ -n "$notary_profile" ]; then
    notary_args=(--keychain-profile "$notary_profile")
  elif [ -n "${APPLE_API_KEY_PATH:-}" ]; then
    [ -n "${APPLE_API_KEY:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ] || die "APPLE_API_KEY_PATH needs APPLE_API_KEY (key id) and APPLE_API_ISSUER"
    notary_args=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER")
  elif [ -n "${APPLE_ID:-}" ]; then
    [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] || die "APPLE_ID needs APPLE_PASSWORD (app-specific) and APPLE_TEAM_ID"
    notary_args=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
  else
    die "no notarization credentials: pass --notary-profile, set APPLE_API_KEY_PATH/APPLE_API_KEY/APPLE_API_ISSUER or APPLE_ID/APPLE_PASSWORD/APPLE_TEAM_ID, or use --no-notarize"
  fi
fi

version="$(node -p "require('$tauri_dir/tauri.conf.json').version")"
product="$(node -p "require('$tauri_dir/tauri.conf.json').productName")"
file_base="$(printf '%s' "$product" | tr ' ' '-')_${version}_${label}"
out="$desktop/release/$version/macos-$arch"
app="$tauri_dir/target/$triple/release/bundle/macos/$product.app"

# --- build ----------------------------------------------------------------------------------------
if [ "$skip_build" = 0 ]; then
  step "Building the CLI"
  (cd "$repo" && pnpm turbo run build --filter=@spinxsca/cli...)
  step "Staging the sidecar for $triple"
  node "$here/stage-sidecar.mjs" --target "$triple"
  step "Building $product.app ($triple)"
  rustup target list --installed | grep -qx "$triple" || rustup target add "$triple"
  # Tauri must neither sign nor notarize: nested code has to be signed first, by this script.
  (cd "$desktop" && env -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD -u APPLE_SIGNING_IDENTITY \
    -u APPLE_ID -u APPLE_PASSWORD -u APPLE_TEAM_ID -u APPLE_API_KEY -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH \
    -u TAURI_SIGNING_PRIVATE_KEY -u TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
    pnpm tauri build --target "$triple" --bundles app --no-sign)
fi
[ -d "$app" ] || die "$app was not built"
[ -x "$app/Contents/Resources/sidecar/node/bin/node" ] || die "the app has no sidecar runtime (stage-sidecar.mjs)"

# --- sign -----------------------------------------------------------------------------------------
sign() { # sign <path> [extra codesign args…]
  local target="$1"; shift
  local args=(--force --sign "$identity")
  if [ "$identity" = "-" ]; then
    args+=(--timestamp=none)
  else
    args+=(--timestamp --options runtime)
    [ -n "$keychain" ] && args+=(--keychain "$keychain")
  fi
  codesign "${args[@]}" "$@" "$target"
}

step "Signing nested code"
node_bin="$app/Contents/Resources/sidecar/node/bin/node"
count=0
while IFS= read -r -d '' f; do
  case "$(file -b "$f")" in
    Mach-O*)
      if [ "$f" = "$node_bin" ]; then
        if [ "$identity" = "-" ]; then sign "$f"; else sign "$f" --entitlements "$entitlements"; fi
      else
        sign "$f"
      fi
      count=$((count + 1))
      ;;
  esac
done < <(find "$app/Contents/Resources" "$app/Contents/Frameworks" -type f -print0 2>/dev/null)
echo "signed $count nested Mach-O files"
step "Signing the app"
while IFS= read -r -d '' f; do sign "$f"; done < <(find "$app/Contents/MacOS" -type f -print0)
sign "$app"
codesign --verify --deep --strict --verbose=2 "$app"

notarize_file() { # notarize_file <file>
  local file="$1" result id status
  echo "submitting $(basename "$file") for notarization (this can take several minutes)"
  result="$(xcrun notarytool submit "$file" "${notary_args[@]}" --wait --output-format json)" || {
    echo "$result" >&2; die "notarytool submit failed"
  }
  id="$(printf '%s' "$result" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).id??""))')"
  status="$(printf '%s' "$result" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).status??""))')"
  if [ "$status" != Accepted ]; then
    [ -n "$id" ] && xcrun notarytool log "$id" "${notary_args[@]}" >&2 || true
    die "notarization of $(basename "$file") ended with status '$status'"
  fi
  echo "notarized ($id)"
}

if [ "$notarize" = 1 ]; then
  step "Notarizing the app"
  ditto -c -k --keepParent "$app" "$work/app.zip"
  notarize_file "$work/app.zip"
  xcrun stapler staple "$app"
  spctl --assess --type execute --verbose=4 "$app"
fi

# --- DMG ------------------------------------------------------------------------------------------
rm -rf "$out"
mkdir -p "$out"
dmg="$out/$file_base.dmg"
step "Creating $(basename "$dmg")"
mkdir -p "$work/dmg"
ditto "$app" "$work/dmg/$product.app"
ln -s /Applications "$work/dmg/Applications"
hdiutil create -volname "$product" -srcfolder "$work/dmg" -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
if [ "$identity" != "-" ]; then
  codesign --force --timestamp --sign "$identity" ${keychain:+--keychain "$keychain"} "$dmg"
fi
if [ "$notarize" = 1 ]; then
  step "Notarizing the DMG"
  notarize_file "$dmg"
  xcrun stapler staple "$dmg"
  spctl --assess --type open --context context:primary-signature --verbose=4 "$dmg"
fi

# --- updater archive ------------------------------------------------------------------------------
if [ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
  step "Creating the updater archive"
  updater="$out/$file_base.app.tar.gz"
  COPYFILE_DISABLE=1 tar -czf "$updater" -C "$(dirname "$app")" "$product.app"
  (cd "$desktop" && pnpm tauri signer sign "$updater" >/dev/null)
  [ -f "$updater.sig" ] || die "tauri signer did not write $updater.sig"
fi

cp "$tauri_dir/sidecar/manifest.json" "$out/sidecar-manifest.json"
# shellcheck disable=SC2046
(cd "$out" && shasum -a 256 $(ls ./*.dmg ./*.tar.gz 2>/dev/null | sed 's|^\./||') > SHA256SUMS)

step "Done"
if [ "$identity" = "-" ]; then
  echo "unsigned build (ad-hoc signature). After copying it to another Mac, clear the quarantine flag:"
  echo "  xattr -dr com.apple.quarantine \"/Applications/$product.app\""
elif [ "$notarize" = 0 ]; then
  echo "signed but not notarized: Gatekeeper rejects it on other Macs until it is notarized."
fi
ls -lh "$out"
