HepatizonCore (Linux x64)
Version: 0.0.1
========================================================================

Thank you for downloading HepatizonCore.
This package contains two versions of the application:

1. hepatizoncore_gui
2. hepatizoncore_cli

========================================================================
HOW TO RUN THE GUI (Desktop App)
========================================================================
1. Open a terminal in this directory.
2. Grant execution permissions:
   chmod +x hepatizoncore_gui

3. Run the application:
   ./hepatizoncore_gui

========================================================================
HOW TO RUN THE CLI (Interactive Shell)
========================================================================
This application runs as a secure, interactive shell.

1. Open a terminal in this directory.
2. Grant execution permissions:
   chmod +x hepatizoncore_cli

3. Start the secure shell:
   ./hepatizoncore_cli

   (You should see a prompt like 'hepatizon> ')

4. Usage Example inside the shell:
   
   > init --path my_vault
   > open --path my_vault
     (Enter password when prompted)
   
   > add --key "github_token" --value "12345"
   > get --key "github_token"
   > exit

========================================================================
TROUBLESHOOTING
========================================================================
- "Command not found" or "Permission denied":
  Make sure you ran 'chmod +x' on the executables and are using the './' 
  prefix (e.g., ./hepatizoncore_cli).

- "error while loading shared libraries":
  This means you do not have the Qt 6 runtime installed.
  
  To fix this on Ubuntu/Debian:
     sudo apt update
     sudo apt install qt6-base-dev

  To fix this on Fedora:
     sudo dnf install qt6-qtbase-devel

========================================================================
LEGAL & LICENSE
========================================================================
HepatizonCore is licensed under the GNU General Public License v3.0 (GPLv3).
See THIRDPARTY_NOTICES.txt for full attribution.