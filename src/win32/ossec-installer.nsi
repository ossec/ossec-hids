; include Modern UI
!include "MUI.nsh"

; include nsProcess
!addincludedir "nsProcess"
!addplugindir "nsProcess"
!include "nsProcess.nsh"

; include SimpleSC
!addplugindir "SimpleSC"

; output file
!ifndef OutFile
    !define OutFile "ossec-win32-agent.exe"
!endif

; general
!define MUI_ICON favicon.ico
!define MUI_UNICON ossec-uninstall.ico
!define VERSION "2.7.1"
!define NAME "OSSEC HIDS"
!define /date CDATE "%b %d %Y at %H:%M:%S"
!define SERVICE "OssecSvc"

Name "${NAME} Windows Agent v${VERSION}"
BrandingText "Copyright (C) 2003 - 2013 Trend Micro Inc."
OutFile "${OutFile}"

InstallDir "$PROGRAMFILES\ossec-agent"
InstallDirRegKey HKLM Software\OSSEC ""

; show (un)installation details
ShowInstDetails show
ShowUninstDetails show

; do not close details pages immediately
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

; interface settings
!define MUI_ABORTWARNING

; pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the install of ${Name}.\r\n\r\nClick next to continue."
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_RUN "$INSTDIR\win32ui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run OSSEC Agent Manager"

; page for choosing components.
!define MUI_COMPONENTSPAGE_TEXT_TOP "Select the options you want to be executed. Click next to continue."
!define MUI_COMPONENTSPAGE_NODESC

; pages to show
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; these have to be defined again to work with the uninstall pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; languages
!insertmacro MUI_LANGUAGE "English"

; function to stop OSSEC service if running
Function .onInit
    ; stop service
    SimpleSC::ExistsService "${SERVICE}"
    Pop $0
    ${If} $0 = 0
        SimpleSC::ServiceIsStopped "${SERVICE}"
        Pop $0
        Pop $1
        ${If} $0 = 0
            ${If} $1 <> 1
                MessageBox MB_OKCANCEL "${NAME} is already installed and the ${SERVICE} service is running. \
                    It will be stopped before continuing." /SD IDOK IDOK ServiceStop
                SetErrorLevel 2
                Abort

                ServiceStop:
                    SimpleSC::StopService "${SERVICE}" 1 30
                    Pop $0
                    ${If} $0 <> 0
                        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure stopping the ${SERVICE} service ($0).\
                            $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                            $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

                        SetErrorLevel 2
                        Abort
                    ${EndIf}
            ${EndIf}
        ${Else}
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure checking status of the ${SERVICE} service ($0).\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

            SetErrorLevel 2
            Abort
        ${EndIf}
    ${EndIf}
    ServiceStopped:
FunctionEnd

; main install section
Section "OSSEC Agent (required)" MainSec
    ; set install type and cwd
    SectionIn RO
    SetOutPath $INSTDIR

    ; clear any errors
    ClearErrors

    ; use real date modified times
    SetDateSave off

    ; overwrite existing files
    SetOverwrite on

    ; create necessary directories
    CreateDirectory "$INSTDIR\bookmarks"
    CreateDirectory "$INSTDIR\rids"
    CreateDirectory "$INSTDIR\syscheck"
    CreateDirectory "$INSTDIR\shared"
    CreateDirectory "$INSTDIR\active-response"
    CreateDirectory "$INSTDIR\active-response\bin"

    ; install files
    File ossec-agent.exe
    File ossec-agent-eventchannel.exe
    File default-ossec.conf
    File manage_agents.exe
    File /oname=win32ui.exe os_win32ui.exe
    File ossec-rootcheck.exe
    File internal_options.conf
    File setup-windows.exe
    File setup-syscheck.exe
    File setup-iis.exe
    File doc.html
    File /oname=shared\rootkit_trojans.txt rootkit_trojans.txt
    File /oname=shared\rootkit_files.txt rootkit_files.txt
    File add-localfile.exe
    File LICENSE.txt
    File /oname=shared\win_applications_rcl.txt rootcheck\db\win_applications_rcl.txt
    File /oname=shared\win_malware_rcl.txt rootcheck\db\win_malware_rcl.txt
    File /oname=shared\win_audit_rcl.txt rootcheck\db\win_audit_rcl.txt
    File help.txt
    File vista_sec.csv
    File /oname=active-response\bin\route-null.cmd route-null.cmd
    File /oname=active-response\bin\restart-ossec.cmd restart-ossec.cmd

    ; use appropriate version of "ossec-agent.exe"
    ${If} ${AtLeastWinVista}
        Delete "$INSTDIR\ossec-agent.exe"
        Rename "$INSTDIR\ossec-agent-eventchannel.exe" "$INSTDIR\ossec-agent.exe"
    ${Else}
        Delete "$INSTDIR\ossec-agent-eventchannel.exe"
    ${Endif}

    ; write registry keys
    WriteRegStr HKLM SOFTWARE\ossec "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayName" "${NAME} ${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayIcon" "${MUI_ICON}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "HelpLink" "http://www.ossec.net/main/support/"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "URLInfoAbout" "http://www.ossec.net"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoRepair" 1
    WriteUninstaller "uninstall.exe"

    ; write version and install information
    VersionInstall:
        FileOpen $0 "$INSTDIR\VERSION.txt" w
        FileWrite $0 "${NAME} v${VERSION} - Installed on ${CDATE}"
        FileClose $0
        IfErrors VersionError VersionComplete
    VersionError:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure saving version to file.$\r$\n$\r$\nFile:$\r$\n$\r$\n$INSTDIR\VERSION.txt\
            $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
            $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE VersionComplete IDRETRY VersionInstall

        SetErrorLevel 2
        Abort
    VersionComplete:
        ClearErrors

    ; create log file
    LogInstall:
        IfFileExists "$INSTDIR\ossec.log" LogComplete
        FileOpen $0 "$INSTDIR\ossec.log" w
        FileClose $0
        IfErrors LogError LogComplete
    LogError:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure creating ossec.log file.$\r$\n$\r$\nFile:$\r$\n$\r$\n$INSTDIR\ossec.log\
            $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
            $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE LogComplete IDRETRY LogInstall

        SetErrorLevel 2
        Abort
    LogComplete:
        ClearErrors

    ; rename ossec.conf if it does not
    ; already exist
    ConfInstall:
        ClearErrors
        IfFileExists "$INSTDIR\ossec.conf" ConfPresent
        Rename "$INSTDIR\default-ossec.conf" "$INSTDIR\ossec.conf"
        IfErrors ConfError ConfPresent
    ConfError:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure renaming configuration file.$\r$\n$\r$\nFrom:$\r$\n$\r$\n$INSTDIR\default-ossec.conf\
            $\r$\n$\r$\nTo:$\r$\n$\r$\n$INSTDIR\ossec.conf$\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
            $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ConfPresent IDRETRY ConfInstall

        SetErrorLevel 2
        Abort
    ConfPresent:
        ClearErrors

    ; handle shortcuts
    SetShellVarContext all

    ; remove shortcuts
    Delete "$SMPROGRAMS\OSSEC\Edit.lnk"
    Delete "$SMPROGRAMS\OSSEC\Uninstall.lnk"
    Delete "$SMPROGRAMS\OSSEC\Documentation.lnk"
    Delete "$SMPROGRAMS\OSSEC\Edit Config.lnk"
    Delete "$SMPROGRAMS\OSSEC\*.*"
    RMDir "$SMPROGRAMS\OSSEC"

    ; create shortcuts
    CreateDirectory "$SMPROGRAMS\OSSEC"
    CreateShortCut "$SMPROGRAMS\OSSEC\Manage Agent.lnk" "$INSTDIR\win32ui.exe" "" "$INSTDIR\win32ui.exe" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Documentation.lnk" "$INSTDIR\doc.html" "" "$INSTDIR\doc.html" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Edit Config.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0

    ; install the service
    ServiceInstall:
        nsExec::ExecToLog '"$INSTDIR\ossec-agent.exe" install-service'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure setting up the ${SERVICE} service.\
                $\r$\n$\r$\nCheck the details for information about the error.\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ServiceInstallComplete IDRETRY ServiceInstall

            SetErrorLevel 2
            Abort
        ${EndIf}
    ServiceInstallComplete:

    ; install files
    Setup:
        nsExec::ExecToLog '"$INSTDIR\setup-windows.exe" "$INSTDIR"'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure running setup-windows.exe.\
                $\r$\n$\r$\nCheck the details for information about the error.\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE SetupComplete IDRETRY Setup

            SetErrorLevel 2
            Abort
        ${EndIf}
    SetupComplete:
SectionEnd

; add IIS logs
Section "Scan and monitor IIS logs (recommended)" IISLogs
    nsExec::ExecToLog '"$INSTDIR\setup-iis.exe" "$INSTDIR"'
SectionEnd

; add integrity checking
Section "Enable integrity checking (recommended)" IntChecking
    nsExec::ExecToLog '"$INSTDIR\setup-syscheck.exe" "$INSTDIR" "enable"'
SectionEnd

; uninstall section
Section "Uninstall"
    ; uninstall the services
    ; this also stops the service as well so it should be done early
    ServiceUninstall:
        nsExec::ExecToLog '"$INSTDIR\ossec-agent.exe" uninstall-service'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailure uninstalling the ${SERVICE} service.\
                $\r$\n$\r$\nCheck the details for information about the error.\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ServiceUninstallComplete IDRETRY ServiceUninstall

            SetErrorLevel 2
            Abort
        ${EndIf}
    ServiceUninstallComplete:

    ; make sure manage_agents.exe is not running
    ManageAgents:
        ${nsProcess::FindProcess} "manage_agents.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFound manage_agents.exe is still running.\
                $\r$\n$\r$\nPlease close it before continuing.\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE ManageAgentsClosed IDRETRY ManageAgents

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    ManageAgentsClosed:

    ; make sure win32ui.exe is not running
    win32ui:
        ${nsProcess::FindProcess} "win32ui.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFound win32ui.exe is still running.\
                $\r$\n$\r$\nPlease close it before continuing.\
                $\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or\
                $\r$\nIgnore to skip this file." /SD IDABORT IDIGNORE win32uiClosed IDRETRY win32ui

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    win32uiClosed:

    ; unload nsProcess
    ${nsProcess::Unload}

    ; remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC"
    DeleteRegKey HKLM SOFTWARE\OSSEC

    ; remove files and uninstaller
    Delete "$INSTDIR\ossec-agent.exe"
    Delete "$INSTDIR\manage_agents.exe"
    Delete "$INSTDIR\ossec.conf"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\*"
    Delete "$INSTDIR\bookmarks\*"
    Delete "$INSTDIR\rids\*"
    Delete "$INSTDIR\syscheck\*"
    Delete "$INSTDIR\shared\*"
    Delete "$INSTDIR\active-response\bin\*"
    Delete "$INSTDIR\active-response\*"
    Delete "$INSTDIR"

    ; remove shortcuts
    SetShellVarContext all
    Delete "$SMPROGRAMS\OSSEC\*.*"
    Delete "$SMPROGRAMS\OSSEC\*"
    RMDir "$SMPROGRAMS\OSSEC"

    ; remove directories used
    RMDir "$INSTDIR\shared"
    RMDir "$INSTDIR\syscheck"
    RMDir "$INSTDIR\bookmarks"
    RMDir "$INSTDIR\rids"
    RMDir "$INSTDIR\active-response\bin"
    RMDir "$INSTDIR\active-response"
    RMDir "$INSTDIR"
SectionEnd
