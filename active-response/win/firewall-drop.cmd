@ECHO OFF
ECHO.

:: Set some variables
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DAT=%%A %%B
FOR /F "TOKENS=1-3 DELIMS=:" %%A IN ("%TIME%") DO SET TIM=%%A:%%B:%%C

:: Block IP Address
SET ACTION=%~1
SET SRCIP=%~3

:: Check for required arguments
IF /I "%ACTION%"=="" GOTO ERROR
IF /I "%2"=="" GOTO ERROR
IF /I "%SRCIP%"=="" GOTO ERROR


IF /I "%ACTION%"=="add" GOTO ADD
IF /I "%ACTION%"=="delete" GOTO DEL

:ERROR
ECHO Invalid argument(s).
ECHO Usage: firewall-drop.cmd ^(add^|delete^) user IP_Address
ECHO Example: firewall-drop.cmd ADD - 1.2.3.4
ECHO %DAT%%TIM% "%~f0" %1 %2 %3 (error) >> "%OSSECPATH%active-response\active-responses.log"
EXIT /B 1

:: Adding IP to be blocked

:ADD
ECHO Adding
netsh advfirewall firewall add rule name="OSSEC-%SRCIP%" dir=in interface=any action=block remoteip=%SRCIP%  
ECHO %DAT%%TIM% "%~f0" %1 %2 %3 >> "%OSSECPATH%active-response\active-responses.log"
GOTO EXIT

:DEL
ECHO Removing
netsh advfirewall firewall delete rule name="OSSEC-%SRCIP%" dir=in
ECHO %DAT%%TIM% "%~f0" %1 %2 %3 >> "%OSSECPATH%active-response\active-responses.log"


:EXIT /B 0: