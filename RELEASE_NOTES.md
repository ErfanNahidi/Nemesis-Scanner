# Nemesis Scanner CLI 4.1.1

This release adds ready-to-install Linux packages and a standalone Windows executable build.

## Installers

- Linux x86_64 AppImage
- Debian/Ubuntu DEB package
- Fedora-compatible RPM package
- Arch Linux package
- Windows x64 executable (built and attached by GitHub Actions after publishing)

The packages bundle the Python runtime and Python dependencies. Nmap remains a system dependency
for actual scans. DEB, RPM, and Arch installers declare Nmap as a package dependency; install Nmap
separately before running the AppImage or Windows executable.

## Data and permissions

Recent-target history and NVD cache files now use the standard per-user data directory instead of
writing into the installed application directory. This allows packaged installations to run as a
regular user.

Use the scanner only for systems you own or are explicitly authorized to assess.
