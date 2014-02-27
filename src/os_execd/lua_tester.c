
#include <stdio.h>
#include "lua_handler.h"


int main()
{

  printf ("starting new\n");
  lua_handler_t *tester = lua_handler_new("test/test_1.lua");
  printf ("starting add\n");
  lua_handler_add(tester, "jrossi","1.1.1.1");
  printf ("starting delete\n");
  lua_handler_delete(tester, "jrossi", "1.1.1.1");
  printf ("starting destory\n");
  lua_handler_destroy(&tester);

  return 0;
}
