; ghostchat Windows installer.
;
; Per-user and unelevated: the program lands in
; %LOCALAPPDATA%\Programs\ghostchat, the shortcuts belong to the current user,
; and uninstalling removes exactly what this script wrote. Keys and settings
; live in %APPDATA%\ghostchat and are never touched by setup or uninstall.
;
; packaging/windows/build-installer.ps1 passes the defines:
;   PRODUCT_VERSION   0.1.0
;   PRODUCT_VERSION4  0.1.0.0   (VERSIONINFO wants four numbers)
;   SOURCE_DIR        dist\windows (ghostchat.exe plus its sidecars)
;   OUTFILE           dist\ghostchat-<version>-windows-x86_64-setup.exe
;   ROOT              repository root (LICENSE, NOTICE, assets)
;
; Built with NSIS 3.13; nothing here needs a plugin beyond what ships with it.

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!ifndef PRODUCT_VERSION
  !error "PRODUCT_VERSION is not defined"
!endif
!ifndef PRODUCT_VERSION4
  !error "PRODUCT_VERSION4 is not defined"
!endif
!ifndef SOURCE_DIR
  !error "SOURCE_DIR is not defined"
!endif
!ifndef OUTFILE
  !error "OUTFILE is not defined"
!endif
!ifndef ROOT
  !error "ROOT is not defined"
!endif

!define APP_NAME "ghostchat"
!define APP_PUBLISHER "ghostchat"
!define APP_URL "https://github.com/aymenmerabta5/ghostchat"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ghostchat"

Name "${APP_NAME}"
BrandingText "${APP_NAME} ${PRODUCT_VERSION}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${APP_NAME}"
InstallDirRegKey HKCU "Software\${APP_NAME}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma

VIProductVersion "${PRODUCT_VERSION4}"
VIAddVersionKey /LANG=1033 "ProductName" "${APP_NAME}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "${APP_NAME} setup"
VIAddVersionKey /LANG=1033 "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=1033 "CompanyName" "${APP_PUBLISHER}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "MIT licensed"

!define MUI_ABORTWARNING
!define MUI_ICON "${ROOT}\assets\ghostchat.ico"
!define MUI_UNICON "${ROOT}\assets\ghostchat.ico"
!define MUI_WELCOMEPAGE_TITLE "${APP_NAME} ${PRODUCT_VERSION}"
!define MUI_WELCOMEPAGE_TEXT "This installs ${APP_NAME} for your Windows account only.$\r$\n$\r$\nIt runs in the notification area: closing the window keeps it receiving messages, and quitting from the tray icon stops it. Start-at-login stays off until you turn it on in the app's settings.$\r$\n$\r$\nNo administrator password is needed."
!define MUI_LICENSEPAGE_TEXT_TOP "${APP_NAME} is MIT licensed. The notice lists what this fork changes and the Unlicense terms of the bitchat protocol it implements."
!define MUI_FINISHPAGE_RUN "$INSTDIR\ghostchat.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APP_NAME} now"
!define MUI_FINISHPAGE_LINK "${APP_NAME} on GitHub"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${ROOT}\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; A running copy locks ghostchat.exe, so setup and uninstall close it first.
; tasklist + findstr exits 0 and prints a line only when the process is up.
!macro CloseRunningApp prompt
  nsExec::ExecToStack 'cmd /c tasklist /FI "IMAGENAME eq ghostchat.exe" /NH | findstr /I "ghostchat.exe"'
  Pop $0
  Pop $1
  ${If} $0 == "0"
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "${prompt}" IDOK +2
      Abort
    nsExec::Exec 'taskkill /IM ghostchat.exe /F /T'
    Sleep 800
  ${EndIf}
!macroend

Function .onInit
  SetShellVarContext current
  !insertmacro CloseRunningApp "ghostchat is running. Setup will close it so its files can be replaced. Continue?"
FunctionEnd

Function un.onInit
  SetShellVarContext current
  !insertmacro CloseRunningApp "ghostchat is running. Uninstalling closes it. Continue?"
FunctionEnd

Section "ghostchat (required)" SecMain
  SectionIn RO
  SetShellVarContext current
  SetOutPath "$INSTDIR"

  File "${SOURCE_DIR}\ghostchat.exe"
  File "${SOURCE_DIR}\ghostchat.exe.sha256"
  File "${SOURCE_DIR}\ghostchat.exe.json"
  File "${SOURCE_DIR}\THIRD-PARTY-NOTICES.txt"
  File "${ROOT}\LICENSE"
  File "${ROOT}\NOTICE"

  WriteUninstaller "$INSTDIR\Uninstall ghostchat.exe"

  WriteRegStr HKCU "Software\${APP_NAME}" "InstallDir" "$INSTDIR"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKCU "${UNINST_KEY}" "URLInfoAbout" "${APP_URL}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\ghostchat.exe,0"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall ghostchat.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall ghostchat.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1

  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

Section "Start Menu shortcut" SecStartMenu
  SetShellVarContext current
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\ghostchat.exe" "" "$INSTDIR\ghostchat.exe" 0
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\Uninstall ghostchat.exe"
SectionEnd

Section /o "Desktop shortcut" SecDesktop
  SetShellVarContext current
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\ghostchat.exe" "" "$INSTDIR\ghostchat.exe" 0
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The ghostchat program, its hash, provenance and license files."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Add ghostchat and its uninstaller to the Start Menu."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Put a ghostchat shortcut on the desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetShellVarContext current

  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"
  Delete "$DESKTOP\${APP_NAME}.lnk"

  Delete "$INSTDIR\ghostchat.exe"
  Delete "$INSTDIR\ghostchat.exe.sha256"
  Delete "$INSTDIR\ghostchat.exe.json"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\Uninstall ghostchat.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "Software\${APP_NAME}"
SectionEnd
