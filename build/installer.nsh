; Custom NSIS Installer & Uninstaller behavior for OSIEN Probe
; Respectful uninstall confirmation: never asks for a reason, just lets the user keep or uninstall.

!macro customUnInit
  MessageBox MB_YESNO|MB_ICONQUESTION "You are about to uninstall OSIEN Probe.$\r$\n$\r$\nWe never ask why — click Yes to remove OSIEN Probe, or No to keep using it." IDYES +2
  Abort
!macroend
