#if __ANDROID__
#include <stdio.h>
#include <time.h>

time_t timegm(struct tm *tm)
{
    time_t ret;
    char *tz;

   tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();
    return ret;
}

int getline(char *buf, int size, FILE *file) {
	char *start = buf;
	int cnt = 0;
	int eof = 0;
	int eol = 0;
	int c;

	if (size < 1) {
		return 0;
	}

	while (cnt < (size - 1)) {
		c = getc(file);
		if (c == EOF) {
			eof = 1;
			break;
		}

		*(buf + cnt) = c;
		cnt++;

		if (c == '\n') {
			eol = 1;
			break;
		}
	}

	/* Null terminate what we've read */
	*(buf + cnt) = '\0';

	if (eof) {
		return -1;
	} else if (eol) {
		return buf - start;
	} else {
		return -1; // longer than the size to read
	}
}
#endif
