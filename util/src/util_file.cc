#include <util_file.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int create_dir(const char* dir, mode_t mode)
{
	char* tmp = strdup(dir);
	size_t len = strlen(dir);
	for(size_t i = 0; i < len; ++i){
		if(i&&tmp[i] == '/'){
			tmp[i] = 0;
			if(access(tmp, F_OK)){
				mkdir(tmp, mode);
			}
			tmp[i] = '/';
		}
	}

	mkdir(tmp, mode);
	free(tmp);
	return 0;
}
