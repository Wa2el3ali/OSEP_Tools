#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ('powershell -c netsh advfirewall firewall add rule name="RDP_3389" protocol=TCP dir=in localip=192.168.118.121 localport=3389 action=allow');
  i = system ('powershell -c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f');
  i = system ('powershell -c netsh advfirewall firewall set rule group="remote desktop" new enable=Yes');
  
  return 0;
}
