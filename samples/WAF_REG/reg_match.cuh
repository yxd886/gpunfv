#ifndef GPU_SIMPLE_RE_MATCH
#define GPU_SIMPLE_RE_MATCH

/*
 @brief search for regexp anywhere in the text and return the index that matches
 @param regular expression string
 @param string to perform the regex on
 */
__device__ int
match(char *regexp, char *text)
{
    if (regexp[0] == '^')
        return matchhere(regexp+1, text);
    do { //should check if the string is empty
        if (matchhere(regexp, text))
            return 1;
    }while(*text++ != '\0');
    return 0;
}

__device__ int
matchhere(char *regexp, char *text)
{
    if (regexp[0] == '\0')
        return 1;
    if (regexp[1] == '*')
        return matchstar(regexp[0], regexp+2, text);
    if (regexp[1] == '+')
        return matchplus(regexp[0], regexp+2, text);
    if (regexp[0] == '\0' && regexp[1] == '\0')
        return *text == '\0';
    if (*text != '\0' && (regexp[0] == '.' || regexp[0] == *text))
        return matchhere(regexp + 1, text + 1);
    return 0;
}

/* matchstar: leftmost longest search for c*regexp */
__device__ int
matchstar(int c, char *regexp, char *text)
{
    char *t;
    for (t = text; *t != '\0' && (*t == c || c == '.'); t++)
        ;
    do {        /* * matches zero or more */
        if (matchhere(regexp, t))
            return 1;
    } while (t-- > text);
    return 0;
}

__device__ int
matchplus(int c, char *regexp, char *text)
{
    int i = 0;
    do { //a matches one or more instances
        if (matchhere(regexp, text))
            if (i == 0)
                i++;
            else
                return 1;
    } while (*text != '\0' && (*text++ == c || c == '.'));
    return 0;
}

#endif