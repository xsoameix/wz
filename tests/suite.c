#include "check_portable.h"
#include "file.h"

int
main(int argc, char ** argv) {
  int failed;
  SRunner * runner = srunner_create(make_file_suite());
  srunner_run_all(runner, CK_NORMAL);
  failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  return failed;
}
