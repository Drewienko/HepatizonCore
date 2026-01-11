HepatizonCore (Windows x64)
Version: 0.0.1
========================================================================

Thank you for downloading HepatizonCore.
This package contains two versions of the application:

1. hepatizoncore_gui.exe
2. hepatizoncore_cli.exe

========================================================================
HOW TO RUN THE GUI (Desktop App)
========================================================================
1. Double-click "hepatizoncore_gui.exe".
2. No installation is required.
3. If Windows SmartScreen warns you, click "More Info" -> "Run Anyway".

========================================================================
HOW TO RUN THE CLI (Interactive Shell)
========================================================================
This application runs as a secure, interactive shell. You do not pass 
commands directly from PowerShell; instead, you enter the application 
first.

1. Open a terminal in this folder:
   - Hold Shift + Right-click the folder background.
   - Select "Open PowerShell window here".

2. Start the shell:
   .\hepatizoncore_cli.exe

   (You should see a prompt like 'hepatizon> ' or similar)

3. Usage Example inside the shell:
   
   > init --path my_vault
   > open --path my_vault
     (Enter password when prompted)
   
   > add --key "github_token" --value "12345"
   > get --key "github_token"
   > exit

========================================================================
TROUBLESHOOTING
========================================================================
- Missing DLL Errors: 
  Ensure you have extracted ALL files. The .exe and .dll files must 
  stay in the same folder.

========================================================================
LEGAL & LICENSE
========================================================================
HepatizonCore is licensed under the GNU General Public License v3.0 (GPLv3).
See THIRDPARTY_NOTICES.txt for full attribution.