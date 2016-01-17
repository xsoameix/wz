#include <check.h>
#include "suite.h"

int
main(int argc, char ** argv) {
  int failed;
  SRunner * runner = srunner_create(make_wzfile_suite());
  srunner_run_all(runner, CK_NORMAL);
  failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  return failed;
}
