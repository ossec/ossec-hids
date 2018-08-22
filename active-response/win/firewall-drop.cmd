REM block IP address
SET ACTION=%~1
SET SRCIP=%~3
echo Will will %ACTION% IP %SRCIP%

IF "%ACTION%"=="add" (
  ECHO adding
	netsh advfirewall firewall add rule name="OSSEC-%SRCIP%" dir=in interface=any action=block remoteip=%SRCIP%
) ELSE (
  ECHO removing
  netsh advfirewall firewall delete rule name="OSSEC-%SRCIP%" dir=in
)
