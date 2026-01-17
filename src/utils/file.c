#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

char *gettempfilename(void) {
	char buf[256];
	strncpy(buf, "/tmp/reaver-XXXXXX", sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	char *s;
	if(!(s = mkdtemp(buf))) return 0;
	else assert(s == buf);
	/* Safe concatenation: buf has 256 bytes, template is 18, ".tmp" is 4, total < 256 */
	strncat(buf, ".tmp", sizeof(buf) - strlen(buf) - 1);
	return strdup(buf);
}

void writefile(const char* fn, const char* contents) {
	if(!fn || !contents) return;
	FILE *f = fopen(fn, "w");
	if(!f) return;
	size_t l = strlen(contents);
	fwrite(contents, l, 1, f);
	fclose(f);
}
