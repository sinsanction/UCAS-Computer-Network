#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "http.h"

#define SPACE_OR_TAB(x)  ((x) == ' '  || (x) == '\t')
#define CR_OR_NEWLINE(x) ((x) == '\r' || (x) == '\n')

int find_http_header(char *data, int len)
{
	char *temp = data;
	int hdr_len = 0;
	char ch = data[len]; /* remember it */

	/* null terminate the string first */
	data[len] = 0;
	while (!hdr_len && (temp = strchr(temp, '\n')) != NULL) {
		temp++;
		if (*temp == '\n') 
			hdr_len = temp - data + 1;
		else if (len > 0 && *temp == '\r' && *(temp + 1) == '\n') 
			hdr_len = temp - data + 2;
	}
	data[len] = ch; /* put it back */

	/* terminate the header if found */
	if (hdr_len) 
		data[hdr_len-1] = 0;

	return hdr_len;
}

char * http_header_str_val(const char* buf, const char *key, const int keylen, 
					char* value, int value_len)
{
	char *temp = strcasestr(buf, key);
	int i = 0;
	
	if (temp == NULL) {
		*value = 0;
		return NULL;
	}

	/* skip whitespace or tab */
	temp += keylen;
	while (*temp && SPACE_OR_TAB(*temp))
		temp++;

	/* if we reached the end of the line, forget it */
	if (*temp == '\0' || CR_OR_NEWLINE(*temp)) {
		*value = 0;
		return NULL;
	}

	/* copy value data */
	while (*temp && !CR_OR_NEWLINE(*temp) && i < value_len-1)
		value[i++] = *temp++;
	value[i] = 0;
	
	if (i == 0) {
		*value = 0;
		return NULL;
	}

	return value;
}


char* http_get_url(char * data, int data_len, char* value, int value_len)
{
	char *ret = data;
	char *temp;
	int i = 0;

	if (strncmp(data, HTTP_GET, sizeof(HTTP_GET)-1)) {
		*value = 0;
		return NULL;
	}
	
	ret += sizeof(HTTP_GET);
	while (*ret && SPACE_OR_TAB(*ret)) 
		ret++;

	temp = ret;
	while (*temp && *temp != ' ' && i < value_len - 1) {
		value[i++] = *temp++;
	}
	value[i] = 0;
	
	return ret;
}

