#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_op.h"
#include "os_regex.h"

#define OSREGEX_TO_PCRE2_FIX                                                                       \
    ("(?<!\\\\)"     /* not preceed by a '\' */                                                    \
     "([+*]) \\?"    /* '+' or '*' (capture group 1) followed by '?' */                            \
     "("             /* start capture group 2 the */                                               \
     "\\)*"          /* Any number of closing parenthese ')' */                                    \
     "(?: [|$] | $)" /* Either '|', '$', or end of string */                                       \
     ")"             /* end of capture group 2 */                                                  \
    )

/* determine the length of an array */
#define ARRAY_LENGTH(_A) (sizeof(_A) / sizeof(_A[0]))

/* definition of a remplacement pattern */
typedef struct _replacement_pattern {
    const char *old;
    const char *new;
    size_t new_sz;
    size_t old_sz;
} replacement_pattern;

/* macro to define an entry in a replacement map */
#define REPLACEMENT_ENTRY(_old, _new)                                                              \
    { .old = _old, .new = _new, .new_sz = sizeof(_new) - 1, .old_sz = sizeof(_old) - 1 }

/* replacement map for ossec regex to perl6 expressions */
const replacement_pattern _replacement_map_regex[] = {
    REPLACEMENT_ENTRY("\\p", "[()*+,.:;\\<=>?\\[\\]!\"'#%&$|{}-]"),
    REPLACEMENT_ENTRY("\\s", "[ ]"),
    REPLACEMENT_ENTRY("\\W", "[^A-Za-z0-9@_-]"),
    REPLACEMENT_ENTRY("\\w", "[A-Za-z0-9@_-]"),
    REPLACEMENT_ENTRY("\\d", "[0-9]"),
    REPLACEMENT_ENTRY("\\D", "[^0-9]"),
    REPLACEMENT_ENTRY("\\S", "[^ ]"),
    REPLACEMENT_ENTRY("\\.", "(?s:.)"),
    REPLACEMENT_ENTRY("$", "(?!\\n)$"),
    REPLACEMENT_ENTRY(".", "\\."),
    REPLACEMENT_ENTRY("[", "\\["),
    REPLACEMENT_ENTRY("]", "\\]"),
    REPLACEMENT_ENTRY("{", "\\{"),
    REPLACEMENT_ENTRY("}", "\\}"),
    REPLACEMENT_ENTRY("+", "\\+"),
    REPLACEMENT_ENTRY("?", "\\?"),
    REPLACEMENT_ENTRY("*", "\\*")};

/* replacement map for match expressions */
const replacement_pattern _replacement_map_match[] = {
    REPLACEMENT_ENTRY(".", "\\."), REPLACEMENT_ENTRY("[", "\\["),  REPLACEMENT_ENTRY("]", "\\]"),
    REPLACEMENT_ENTRY("{", "\\{"), REPLACEMENT_ENTRY("}", "\\}"),  REPLACEMENT_ENTRY("+", "\\+"),
    REPLACEMENT_ENTRY("?", "\\?"), REPLACEMENT_ENTRY("*", "\\*"),  REPLACEMENT_ENTRY("(", "\\("),
    REPLACEMENT_ENTRY(")", "\\)"), REPLACEMENT_ENTRY("\\", "\\\\")};

int OSRegex_ConvertRegex(const char *pattern, char **converted_pattern_ptr);
int OSRegex_ConvertMatch(const char *pattern, char **converted_pattern_ptr);

int OSRegex_Convert(const char *pattern, char **converted_pattern_ptr, uint32_t map)
{
    *converted_pattern_ptr = NULL;
    switch (map) {
        case OS_CONVERT_REGEX:
            return OSRegex_ConvertRegex(pattern, converted_pattern_ptr);
        case OS_CONVERT_MATCH:
            return OSRegex_ConvertMatch(pattern, converted_pattern_ptr);
            break;
        default:
            return (0);
    }
}

int OSRegex_ConvertRegex(const char *pattern, char **converted_pattern_ptr)
{
    char *converted_pattern = NULL;
    size_t converted_pattern_size = 0UL;
    size_t converted_pattern_offset = 0UL;
    size_t pattern_offset = 0UL;
    size_t pattern_size = strlen(pattern);
    const char *replacement = NULL;
    size_t replacement_size = 0UL;
    const size_t map_size = ARRAY_LENGTH(_replacement_map_regex);
    const replacement_pattern *map = _replacement_map_regex;
    size_t i;
    const char *p = NULL;
    const char *star_ungreedy = "*?";
    const char *plus_ungreedy = "+?";
    pcre2_code *preg = NULL;
    int error = 0;
    PCRE2_SIZE erroroffset = 0;
    PCRE2_UCHAR *final_converted_pattern = NULL;
    PCRE2_SIZE final_converted_pattern_len = 0;

    for (pattern_offset = 0UL; pattern_offset < pattern_size; pattern_offset++) {
        p = &pattern[pattern_offset];
        replacement = NULL;
        replacement_size = 0UL;

        if (pattern_offset >= 2 && pattern[pattern_offset - 2] == '\\') {
            switch (p[0]) {
                case '*':
                    replacement = star_ungreedy;
                    replacement_size = 2UL;
                    break;
                case '+':
                    replacement = plus_ungreedy;
                    replacement_size = 2UL;
                    break;
                default:
                    break;
            }
        }

        if (!replacement) {
            for (i = 0; i < map_size; i++) {
                if (map[i].old_sz + pattern_offset <= pattern_size &&
                    strncmp(map[i].old, p, map[i].old_sz) == 0) {
                    replacement = map[i].new;
                    replacement_size = map[i].new_sz;
                    pattern_offset += map[i].old_sz - 1;
                    break;
                }
            }
        }

        if (!replacement) {
            /* If it is a special class for ossec */
            if (p[0] == '\\' && pattern_offset + 1 < pattern_size) {
                switch (p[1]) {
                    case 't':
                    case '$':
                    case '(':
                    case ')':
                    case '{':
                    case '}':
                    case '[':
                    case ']':
                    case '\\':
                    case '|':
                    case '<':
                        /* case '>': Only the '<' can be escaped, possibly to not interfer
                         * with XML parsing if nothing to backslash we copy the two current
                         * input pattern characters and move the cursor to the next next char
                         */
                        replacement = p;
                        pattern_offset++;
                        replacement_size = 2UL;
                        break;
                    default:
                        goto conversion_error;
                }
            } else {
                replacement = p;
                replacement_size = 1UL;
            }
        }

        if (converted_pattern_offset + replacement_size >= converted_pattern_size) {
            converted_pattern_size += OS_PATTERN_MAXSIZE;
            converted_pattern = (char *)realloc(converted_pattern, converted_pattern_size);
            if (!converted_pattern) {
                return (0);
            }
        }

        converted_pattern_offset += sprintf(&converted_pattern[converted_pattern_offset], "%.*s",
                                            (int)replacement_size, replacement);
    }

    /*
     * We should remove the '?' for non-greediness when it is the last one => m/([+*])\?(\)*[|]?)$/
     * Because Ossec is only greedy with the last occurencies modifier
     */
    preg = pcre2_compile((PCRE2_SPTR)OSREGEX_TO_PCRE2_FIX, PCRE2_ZERO_TERMINATED, PCRE2_EXTENDED,
                         &error, &erroroffset, NULL);
    if (preg == NULL) {
        goto conversion_error;
    }
    final_converted_pattern_len = converted_pattern_size;
    final_converted_pattern = malloc(final_converted_pattern_len);
    if (pcre2_substitute(preg, (PCRE2_SPTR)converted_pattern, converted_pattern_offset, 0,
                         PCRE2_SUBSTITUTE_GLOBAL, NULL, NULL, (PCRE2_SPTR) "$1$2", 4,
                         final_converted_pattern, &final_converted_pattern_len) > 0) {
        free(converted_pattern);
        *converted_pattern_ptr = (char *)final_converted_pattern;
    } else {
        free(final_converted_pattern);
        *converted_pattern_ptr = converted_pattern;
    }
    pcre2_code_free(preg);

    return (1);

conversion_error:
    if (converted_pattern) {
        free(converted_pattern);
    }

    if (preg) {
        pcre2_code_free(preg);
    }

    return (0);
}

int OSRegex_ConvertMatch(const char *pattern, char **converted_pattern_ptr)
{
    char *converted_pattern = NULL;
    size_t converted_pattern_size = 0UL;
    size_t converted_pattern_offset = 0UL;
    size_t pattern_offset = 0UL;
    size_t pattern_size = strlen(pattern);
    const char *replacement = NULL;
    size_t replacement_size = 0UL;
    const size_t map_size = ARRAY_LENGTH(_replacement_map_match);
    const replacement_pattern *map = _replacement_map_match;
    size_t i;
    const char *p = NULL;

    for (pattern_offset = 0UL; pattern_offset < pattern_size; pattern_offset++) {
        p = &pattern[pattern_offset];
        replacement = NULL;
        replacement_size = 0UL;
        for (i = 0; i < map_size; i++) {
            if (map[i].old_sz + pattern_offset <= pattern_size &&
                strncmp(map[i].old, p, map[i].old_sz) == 0) {
                replacement = map[i].new;
                replacement_size = map[i].new_sz;
                pattern_offset += map[i].old_sz - 1;
                break;
            }
        }
        if (!replacement) {
            replacement = p;
            replacement_size = 1UL;
        }

        if (converted_pattern_offset + replacement_size >= converted_pattern_size) {
            converted_pattern_size += OS_PATTERN_MAXSIZE;
            converted_pattern = (char *)realloc(converted_pattern, converted_pattern_size);
            if (!converted_pattern) {
                return (0);
            }
        }

        converted_pattern_offset += sprintf(&converted_pattern[converted_pattern_offset], "%.*s",
                                            (int)replacement_size, replacement);
    }

    *converted_pattern_ptr = converted_pattern;

    return (1);
}
