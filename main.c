#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#ifndef ANDROID
#include <sepol/sepol.h>
#include <sepol/policydb.h>
#endif
#include <dlfcn.h>
#include <limits.h>

/* The MODE argument to `dlopen' contains one of the following: */
#define RTLD_LAZY	0x00001	/* Lazy function call binding.  */
#define RTLD_NOW	0x00002	/* Immediate function call binding.  */
#define	RTLD_BINDING_MASK   0x3	/* Mask of binding time value.  */
#define RTLD_NOLOAD	0x00004	/* Do not load the object.  */
#define RTLD_DEEPBIND	0x00008	/* Use deep binding.  */

#define PROT_READ	0x1		/* Page can be read.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */
#define PATH_MAX	4096	/* # chars in a path name including nul */
#define MAP_FAILED	((void *) -1)

int main(int argc, char *argv[]){

	if(argc != 3) {
		printf("Usage:\n");
		printf("./policytool [path of old version] [num of target version]\n");
		printf("For example:\n");
		printf("./policytool  ./policy.32   31\n");
		return 0;
	}

	int target_version = atoi(argv[2]);
	FILE *file;
	char path[PATH_MAX];
	struct stat sb;
	size_t size;
	void *map, *data;
	int fd= -1;
	sepol_policydb_t *policydb;
	sepol_policy_file_t *pf;


	int (*policy_file_create)(sepol_policy_file_t **) = NULL;
	void (*policy_file_free)(sepol_policy_file_t *) = NULL;
	void (*policy_file_set_mem)(sepol_policy_file_t *, char*, size_t) = NULL;
	int (*policydb_create)(sepol_policydb_t **) = NULL;
	void (*policydb_free)(sepol_policydb_t *) = NULL;
	int (*policydb_read)(sepol_policydb_t *, sepol_policy_file_t *) = NULL;
	int (*policydb_set_vers)(sepol_policydb_t *, unsigned int) = NULL;
	int (*policydb_to_image)(sepol_handle_t *, sepol_policydb_t *, void **, size_t *) = NULL;

	void *libsepolh = NULL;
	libsepolh = dlopen("./libsepol.so.2", RTLD_NOW);
	if (libsepolh) {
		policy_file_create = dlsym(libsepolh, "sepol_policy_file_create");
		policy_file_free = dlsym(libsepolh, "sepol_policy_file_free");
		policy_file_set_mem = dlsym(libsepolh, "sepol_policy_file_set_mem");
		policydb_create = dlsym(libsepolh, "sepol_policydb_create");
		policydb_free = dlsym(libsepolh, "sepol_policydb_free");
		policydb_read = dlsym(libsepolh, "sepol_policydb_read");
		policydb_set_vers = dlsym(libsepolh, "sepol_policydb_set_vers");
		policydb_to_image = dlsym(libsepolh, "sepol_policydb_to_image");
	}
	else{
		printf("open libsepol.so.2 failed\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY | O_CLOEXEC);

	if (fstat(fd, &sb) < 0) {
		printf("SELinux:  Could not stat policy file\n");
			goto close;
	}

	size = sb.st_size;
	data = map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(map == MAP_FAILED){
		printf("map policy file failed\n");
		goto close;
	}

	if (policy_file_create(&pf))
			goto unmap;
	if (policydb_create(&policydb)) {
			policy_file_free(pf);
			goto unmap;
		}
	policy_file_set_mem(pf, data, size);
	if (policydb_read(policydb, pf)) {
			policy_file_free(pf);
			policydb_free(policydb);
			goto unmap;
		}
	if (policydb_set_vers(policydb, target_version) ||
			policydb_to_image(NULL, policydb, &data, &size)) {
			/* Downgrade failed, keep searching. */
			printf("convert to target version failed\n");
			policy_file_free(pf);
			policydb_free(policydb);
			munmap(map, sb.st_size);
			close(fd);
			return -1;
		}
	else{
		char str1[10] = "policy.";
		strcat(str1, argv[2]);
		file = fopen(str1,"w");
		if(file == NULL){
			printf("create new version file failed\n");
			return -1;
		}

		if (fwrite(data,1,size,file) == EOF) {
			printf("write data to file failed\n");
			fclose(file);
			return -1;
		}
		printf("Downgrade to version %d  Success!!!\n",target_version);
		fclose(file);
	}
	policy_file_free(pf);
	policydb_free(policydb);

unmap:
	if (data != map)
		free(data);
	munmap(map, sb.st_size);
close:
	close(fd);
	return 0;
	}