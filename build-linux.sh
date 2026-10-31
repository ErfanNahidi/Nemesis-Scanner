#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VERSION="$(python -c 'from core.core import VERSION; print(VERSION)')"
ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] || { echo "Only x86_64 builds are supported by this script." >&2; exit 1; }

for command in python rpmbuild dpkg-deb tar zstd; do
    command -v "$command" >/dev/null || { echo "Missing build tool: $command" >&2; exit 1; }
done
command -v nmap >/dev/null || { echo "Nmap is required at runtime; install it before using the scanner." >&2; }

if [[ "${SKIP_PYINSTALLER:-0}" != "1" ]]; then
    python -m PyInstaller --noconfirm --clean --onefile --name nemesis-scanner \
        --collect-submodules nmap \
        --add-data "core/static_vulns.json:core" \
        cli.py
fi

DIST="$ROOT/dist"
STAGE="$ROOT/build/package-root"
rm -rf "$STAGE"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/doc/nemesis-scanner-cli"
install -m 0755 "$DIST/nemesis-scanner" "$STAGE/usr/bin/nemesis-scanner"
install -m 0644 README.md README_FA.md MANUAL.md LICENSE \
    "$STAGE/usr/share/doc/nemesis-scanner-cli/"

DEB_ROOT="$ROOT/build/deb-root"
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"
cp -a "$STAGE/usr" "$DEB_ROOT/"
cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: nemesis-scanner-cli
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: amd64
Depends: nmap
Maintainer: Nemesis Scanner contributors
Description: Nemesis Scanner command-line network assessment tool
 Python-based Nmap front end with interactive and direct command-line modes.
EOF
dpkg-deb --root-owner-group --build "$DEB_ROOT" "$DIST/nemesis-scanner-cli_${VERSION}_amd64.deb"

RPM_TOP="$ROOT/build/rpmbuild"
mkdir -p "$RPM_TOP/SOURCES" "$RPM_TOP/SPECS" "$RPM_TOP/BUILD" "$RPM_TOP/BUILDROOT" "$RPM_TOP/RPMS" "$RPM_TOP/SRPMS" "$RPM_TOP/tmp"
cp "$DIST/nemesis-scanner" "$RPM_TOP/SOURCES/nemesis-scanner"
cp README.md README_FA.md MANUAL.md LICENSE "$RPM_TOP/SOURCES/"
cat > "$RPM_TOP/SPECS/nemesis-scanner-cli.spec" <<EOF
Name:           nemesis-scanner-cli
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        Nemesis Scanner command-line network assessment tool
License:        MIT
URL:            https://github.com/ErfanNahidi/Nemesis-Scanner
Source0:        nemesis-scanner
Source1:        README.md
Source2:        README_FA.md
Source3:        MANUAL.md
Source4:        LICENSE
Requires:       nmap
BuildArch:      x86_64

%description
Standalone command-line scanner interface using the system Nmap executable.

%prep

%build

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/nemesis-scanner
install -d %{buildroot}%{_docdir}/%{name}
install -pm0644 %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4} %{buildroot}%{_docdir}/%{name}/

%files
%{_bindir}/nemesis-scanner
%{_docdir}/%{name}/README.md
%{_docdir}/%{name}/README_FA.md
%{_docdir}/%{name}/MANUAL.md
%license %{_docdir}/%{name}/LICENSE

%changelog
* $(date '+%a %b %d %Y') Nemesis Scanner contributors - ${VERSION}-1
- Initial packaged CLI release
EOF
rpmbuild --define "_topdir $RPM_TOP" --define "_tmppath $RPM_TOP/tmp" \
    -bb "$RPM_TOP/SPECS/nemesis-scanner-cli.spec"
cp "$RPM_TOP/RPMS/x86_64/nemesis-scanner-cli-${VERSION}-1."*.rpm \
    "$DIST/nemesis-scanner-cli-${VERSION}-1.x86_64.rpm"

ARCH_ROOT="$ROOT/build/arch-root"
rm -rf "$ARCH_ROOT"
mkdir -p "$ARCH_ROOT/usr/bin" "$ARCH_ROOT/usr/share/doc/nemesis-scanner-cli"
install -m 0755 "$DIST/nemesis-scanner" "$ARCH_ROOT/usr/bin/nemesis-scanner"
install -m 0644 README.md README_FA.md MANUAL.md LICENSE \
    "$ARCH_ROOT/usr/share/doc/nemesis-scanner-cli/"
cat > "$ARCH_ROOT/.PKGINFO" <<EOF
pkgname = nemesis-scanner-cli
pkgbase = nemesis-scanner-cli
pkgver = ${VERSION}-1
pkgdesc = Nemesis Scanner command-line network assessment tool
url = https://github.com/ErfanNahidi/Nemesis-Scanner
builddate = $(date +%s)
packager = Nemesis Scanner contributors
size = $(du -sb "$ARCH_ROOT" | cut -f1)
arch = x86_64
license = MIT
depend = nmap
EOF
tar --zstd -cf "$DIST/nemesis-scanner-cli-${VERSION}-1-x86_64.pkg.tar.zst" \
    -C "$ARCH_ROOT" .PKGINFO usr

APPDIR="$ROOT/build/NemesisScanner.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/doc/nemesis-scanner-cli"
install -m 0755 "$DIST/nemesis-scanner" "$APPDIR/usr/bin/nemesis-scanner"
install -m 0644 README.md README_FA.md MANUAL.md LICENSE \
    "$APPDIR/usr/share/doc/nemesis-scanner-cli/"
install -m 0644 assets/nemesis-scanner.png "$APPDIR/nemesis-scanner.png"
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/nemesis-scanner" "$@"
EOF
chmod 0755 "$APPDIR/AppRun"
cat > "$APPDIR/nemesis-scanner.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Nemesis Scanner CLI
Comment=Command-line network assessment tool
Exec=nemesis-scanner
Icon=nemesis-scanner
Terminal=true
Categories=Utility;Security;
EOF
if [[ -n "${APPIMAGETOOL:-}" && -x "$APPIMAGETOOL" ]]; then
    export PATH="$(dirname "$APPIMAGETOOL"):$PATH"
    if [[ -n "${APPIMAGE_RUNTIME:-}" ]]; then
        "$APPIMAGETOOL" --runtime-file "$APPIMAGE_RUNTIME" "$APPDIR" \
            "$DIST/NemesisScanner-CLI-${VERSION}-x86_64.AppImage"
    else
        "$APPIMAGETOOL" "$APPDIR" "$DIST/NemesisScanner-CLI-${VERSION}-x86_64.AppImage"
    fi
else
    echo "APPIMAGETOOL is not set to an executable; AppImage build skipped."
fi

echo "Linux packages created in $DIST"
