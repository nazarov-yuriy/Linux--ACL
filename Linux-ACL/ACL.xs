#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/acl.h>
#include <errno.h>
#ifdef __cplusplus
}
#endif

#define PACKAGE_NAME "Linux::ACL"

MODULE = Linux::ACL		PACKAGE = Linux::ACL

 # getfacl(filename)

void
getfacl(file_name)
     SV * file_name;
     PPCODE:
{
  char *file_string;        /* c-string version of file_name */
  int file_string_length;   /* need to pass a variable to SvPV */
  file_string = SvPV(file_name,file_string_length);
  printf("Hello, '%s'\n", file_string);
  XSRETURN_YES;
}