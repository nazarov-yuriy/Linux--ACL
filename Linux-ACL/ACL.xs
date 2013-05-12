#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/acl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#ifdef __cplusplus
}
#endif

#define USER_KEY "user"
#define USER_KEY_LENGTH 4
#define GROUP_KEY "group"
#define GROUP_KEY_LENGTH 5
#define OTHER_KEY "other"
#define OTHER_KEY_LENGTH 5
#define MASK_KEY "mask"
#define MASK_KEY_LENGTH 4
#define USER_OBJ_KEY "uperm"
#define USER_OBJ_KEY_LENGTH 5
#define GROUP_OBJ_KEY "gperm"
#define GROUP_OBJ_KEY_LENGTH 5

void add_to_hash(HV* hash, acl_entry_t* ent, char *key, U32 key_len){
	acl_permset_t permset;
	HV* perm_hash = newHV();
	
	acl_get_permset(*ent, &permset);

	hv_store(perm_hash, "r", 1, newSViv( acl_get_perm(permset, ACL_READ) ), 0);
	hv_store(perm_hash, "w", 1, newSViv( acl_get_perm(permset, ACL_WRITE) ), 0);
	hv_store(perm_hash, "x", 1, newSViv( acl_get_perm(permset, ACL_EXECUTE) ), 0);

	hv_store(hash, key, key_len, newRV_noinc((SV*) perm_hash), 0);
}

/*
 * Exported code
 */

#define PACKAGE_NAME "Linux::ACL"

MODULE = Linux::ACL		PACKAGE = Linux::ACL

# getfacl(filename)

void
getfacl(file_name)
     SV * file_name;
     PPCODE:
{
	char *file_string;
	int file_string_length;
	HV* ret_acl;
	HV* ret_acl_uperm;
	HV* ret_acl_gperm;
	acl_entry_t ent;
	struct stat st;
	acl_t acl;
	acl_permset_t permset;
	int ret;
	
	file_string = SvPV(file_name,file_string_length);
	
	if (stat(file_string, &st) != 0) {
		XSRETURN(0);
	}
	
	acl = acl_get_file(file_string, ACL_TYPE_ACCESS);
	if (acl == NULL) {
		XSRETURN(0);
	}
	
	ret = acl_get_entry(acl, ACL_FIRST_ENTRY, &ent);
	if (ret != 1)
		XSRETURN(0);
	
	ret_acl = newHV();
	ret_acl_uperm = newHV();
	ret_acl_gperm = newHV();
	
	while (ret > 0) {
		acl_tag_t e_type;
		acl_get_tag_type(ent, &e_type);
		char id_str[30];
		U32 id_str_len;
		id_t *id_p;
		
		switch(e_type) {
			case ACL_USER_OBJ:	add_to_hash(ret_acl, &ent, USER_OBJ_KEY,  USER_OBJ_KEY_LENGTH);	break;
			case ACL_GROUP_OBJ:	add_to_hash(ret_acl, &ent, GROUP_OBJ_KEY, GROUP_OBJ_KEY_LENGTH);	break;
			case ACL_MASK:		add_to_hash(ret_acl, &ent, MASK_KEY,      MASK_KEY_LENGTH);	break;
			case ACL_OTHER:		add_to_hash(ret_acl, &ent, OTHER_KEY,     OTHER_KEY_LENGTH);	break;
			case ACL_USER:
				id_p = acl_get_qualifier(ent);
				id_str_len = sprintf(id_str, "%d", *id_p);
				add_to_hash(ret_acl_uperm, &ent, id_str, id_str_len);
				break;
			case ACL_GROUP:
				id_p = acl_get_qualifier(ent);
				id_str_len = sprintf(id_str, "%d", *id_p);
				add_to_hash(ret_acl_gperm, &ent, id_str, id_str_len);
				break;
		}
		ret = acl_get_entry(acl, ACL_NEXT_ENTRY, &ent);
	}
	hv_store(ret_acl, USER_KEY,  USER_KEY_LENGTH,  newRV_noinc((SV*) ret_acl_uperm), 0);
	hv_store(ret_acl, GROUP_KEY, GROUP_KEY_LENGTH, newRV_noinc((SV*) ret_acl_gperm), 0);

	XPUSHs(sv_2mortal(ret_acl));
	XSRETURN(1);
}