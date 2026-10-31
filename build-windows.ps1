$ErrorActionPreference = 'Stop'
python -m pip install --upgrade -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name NemesisScanner `
  --collect-submodules nmap `
  --add-data 'core/static_vulns.json;core' `
  cli.py
New-Item -ItemType Directory -Force -Path 'dist/windows' | Out-Null
Copy-Item 'dist/NemesisScanner.exe' 'dist/windows/NemesisScanner.exe' -Force
