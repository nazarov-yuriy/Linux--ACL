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

void add_to_hash(HV *hash, acl_entry_t *ent, char *key, U32 key_len){
	acl_permset_t permset;
	HV* perm_hash = newHV();
	
	acl_get_permset(*ent, &permset);

	hv_store(perm_hash, "r", 1, newSViv( acl_get_perm(permset, ACL_READ) ), 0);
	hv_store(perm_hash, "w", 1, newSViv( acl_get_perm(permset, ACL_WRITE) ), 0);
	hv_store(perm_hash, "x", 1, newSViv( acl_get_perm(permset, ACL_EXECUTE) ), 0);

	hv_store(hash, key, key_len, newRV_noinc((SV*) perm_hash), 0);
}

void set_perm(acl_entry_t ent, mode_t perm)
{
	acl_permset_t set;

	acl_get_permset(ent, &set);
	if (perm & ACL_READ)
		acl_add_perm(set, ACL_READ);
	else
		acl_delete_perm(set, ACL_READ);
	if (perm & ACL_WRITE)
		acl_add_perm(set, ACL_WRITE);
	else
		acl_delete_perm(set, ACL_WRITE);
	if (perm & ACL_EXECUTE)
		acl_add_perm(set, ACL_EXECUTE);
	else
		acl_delete_perm(set, ACL_EXECUTE);
}

int get_perm_from_hash(HV *hash, const char *key, int key_len){
	HV *perm;
	SV **perm_ref;
	SV **atom_ref;
	int perm_val = 0;
	if(perm_ref = hv_fetch(hash, key, key_len, 0)){
		if (! SvROK(*perm_ref))
			return 0;
		if (SvTYPE((SV *)(perm = (HV *)SvRV(*perm_ref))) != SVt_PVHV)
			return 0;

		if(atom_ref = hv_fetch(perm, "r", 1, 0)){
			if (! SvIOK(*atom_ref))
				return 0;
			perm_val |= SvIV(*atom_ref)?ACL_READ:0;
		}

		if(atom_ref = hv_fetch(perm, "w", 1, 0)){
			if (! SvIOK(*atom_ref))
				return 0;
			perm_val |= SvIV(*atom_ref)?ACL_WRITE:0;
		}

		if(atom_ref = hv_fetch(perm, "x", 1, 0)){
			if (! SvIOK(*atom_ref))
				return 0;
			perm_val |= SvIV(*atom_ref)?ACL_EXECUTE:0;
		}
	}
	return perm_val;
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

# getfacl(filename)

void
setfacl(file_name, acl_hashref)
     SV * file_name;
     SV *acl_hashref;
     PPCODE:
{
	char *file_string;
	int file_string_length;
	acl_t acl = NULL;
	acl_entry_t ent;
	HV *acl_hash;
	HV *user_hash, *group_hash;
	HE *hash_entry;
	SV **hash_ref;
	
	file_string = SvPV(file_name,file_string_length);

	if (! SvROK(acl_hashref))
		XSRETURN_NO;
	if (SvTYPE((SV *)(acl_hash = (HV *)SvRV(acl_hashref))) != SVt_PVHV)
		XSRETURN_NO;
	
	if(hash_ref = hv_fetch(acl_hash, USER_KEY, USER_KEY_LENGTH, 0)){
		if (! SvROK(*hash_ref))
			XSRETURN_NO;
		if (SvTYPE((SV *)(user_hash = (HV *)SvRV(*hash_ref))) != SVt_PVHV)
			XSRETURN_NO;
	}

	if(hash_ref = hv_fetch(acl_hash, GROUP_KEY, GROUP_KEY_LENGTH, 0)){
		if (! SvROK(*hash_ref))
			XSRETURN_NO;
		if (SvTYPE((SV *)(group_hash = (HV *)SvRV(*hash_ref))) != SVt_PVHV)
			XSRETURN_NO;
	}

	acl = acl_init(0);
	if (acl_create_entry(&acl, &ent) == 0){
		acl_set_tag_type(ent, ACL_USER_OBJ);
		set_perm(ent, get_perm_from_hash(acl_hash, USER_OBJ_KEY, USER_OBJ_KEY_LENGTH));
	}
	if (acl_create_entry(&acl, &ent) == 0){
		acl_set_tag_type(ent, ACL_GROUP_OBJ);
		set_perm(ent, get_perm_from_hash(acl_hash, GROUP_OBJ_KEY, GROUP_OBJ_KEY_LENGTH));
	}
	if (acl_create_entry(&acl, &ent) == 0){
		acl_set_tag_type(ent, ACL_MASK);
		set_perm(ent, get_perm_from_hash(acl_hash, MASK_KEY, MASK_KEY_LENGTH));
	}
	if (acl_create_entry(&acl, &ent) == 0){
		acl_set_tag_type(ent, ACL_OTHER);
		set_perm(ent, get_perm_from_hash(acl_hash, OTHER_KEY, OTHER_KEY_LENGTH));
	}

	hv_iterinit(user_hash);
	while(hash_entry = hv_iternext(user_hash)){
		id_t id_p;
		I32 key_len;
		char *key = hv_iterkey(hash_entry, &key_len);
		id_p = atoi(key);
		if (acl_create_entry(&acl, &ent) == 0){
			acl_set_tag_type(ent, ACL_USER);
			acl_set_qualifier(ent, &id_p);
			set_perm(ent, get_perm_from_hash(user_hash, key, key_len));
		}
	}

	hv_iterinit(group_hash);
	while(hash_entry = hv_iternext(group_hash)){
		id_t id_p;
		I32 key_len;
		char *key = hv_iterkey(hash_entry, &key_len);
		id_p = atoi(key);
		if (acl_create_entry(&acl, &ent) == 0){
			acl_set_tag_type(ent, ACL_GROUP);
			acl_set_qualifier(ent, &id_p);
			set_perm(ent, get_perm_from_hash(group_hash, key, key_len));
		}
	}

	acl_set_file(file_string, ACL_TYPE_ACCESS, acl);

	acl_free(acl);
	
	XSRETURN_YES;
}
