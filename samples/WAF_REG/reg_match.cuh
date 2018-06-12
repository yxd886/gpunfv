#ifndef GPU_SIMPLE_RE_MATCH
#define GPU_SIMPLE_RE_MATCH

int
match(char *regexp, char *text);

int
matchhere(char *regexp, char *text);

int
matchstar(int c, char *regexp, char *text);

int
matchplus(int c, char *regexp, char *text);

#endif