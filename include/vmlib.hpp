#ifndef STDLIB_HPP
#define STDLIB_HPP
#include <stdint.h>
#include <windows.h>

VOID MemCpy (_In_ LPVOID const dst, _In_ const LPVOID const src, _In_ const SIZE_T n) {
    const auto a = (uint8_t*) dst;
    const auto b = (const uint8_t*) src;

    for (size_t i = 0; i < n; i++) {
        a [i] = b [i];
    }
}

LPVOID MemSet (_In_ LPVOID const dst, _In_ const INT val, _In_ SIZE_T len) {
    auto ptr = (uint8_t*) dst;
    while (len-- > 0) {
        *ptr++ = val;
    }
    return dst;
}

PCHAR StrCpy (PCHAR dst, const PCHAR src, size_t n) {
    if (!n) {
        return dst;
    }

    PCHAR d = dst;
    size_t copied = 0;

    while (copied < n - 1 && *src) {
        *d++ = *src++;
        copied++;
    }

    *d++ = '\0';
    copied++;

    while (copied < n) {
        *d++ = '\0';
        copied++;
    }

    return dst;
}

size_t StrnCmp (const PCHAR str1, const PCHAR str2, size_t len) {
    while (len && *str1 && (*str1 == *str2)) {
        len--; str1++; str2++;

        if (len == 0) {
            return  0;
        }
    }
    return len ? (unsigned char)*str1 - (unsigned char)*str2 : 0;
}


size_t StrCmp (const PCHAR str1, const PCHAR str2) {
    while (*str1 && *str1 == *str2) {
        str1++; str2++;
    }

    return (uint8_t) *str1 - (uint8_t) *str2;
}

size_t MemCmp (const LPVOID const ptr1, const LPVOID const ptr2, size_t len) {
    const auto *p1 = (const uint8_t*) ptr1;
    const auto *p2 = (const uint8_t*) ptr2;

    while (len--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }

        p1++; p2++;
    }

    return 0;
}

size_t StrLen(const PCHAR str) {
    auto len = 0;
    const auto s_str = str;

    while (s_str[len] != 0x00) {
        len++;
    }

    return len;
}

PCHAR StrCat (PCHAR const dst, const PCHAR const src) {

    size_t len1 = strlen(dst);
    strcpy(dst + len1, src, len1);
    return dst;
}

size_t WcsLen (const wchar_t *const s) {
    size_t len = 0;
    const auto s_str = s;

    while (s_str[len] != 0x0000) {
        len++;
    }

    return len;
}

wchar_t* WcsCpy (wchar_t *dst, const wchar_t *src, size_t n) {
    if (!n) {
        return dst;
    }

    wchar_t *d      = dst;
    size_t copied   = 0;

    while (copied < n - 1 && *src) {
        *d++ = *src++;
        copied++;
    }

    *d++ = L'\0';
    copied++;

    while (copied < n) {
        *d++ = L'\0';
        copied++;
    }

    return dst;
}

size_t WcsCmp (const wchar_t *str1, const wchar_t *str2) {
    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == 0x0000) {
            return 0;
        }
    }
    return *str1 < *str2 ? -1 : +1;
}

wchar_t *WcsCat (wchar_t *const str1, const wchar_t *const str2) {
    size_t len1 = wcslen(str1);
    wcscpy(str1 + len1, str2, len1);
    return str1;
}

wchar_t ToLowerW (const wchar_t c) {
    if (c >= 0x0041 && c <= 0x005A) {
        return c + (0x0061 - 0x0041);
    }

    return c;
}

char ToLowerA (const char c) {
    if (c >= 0x41 && c <= 0x5A) {
        return c + (0x61 - 0x41);
    }

    return c;
}

wchar_t *WcsToLower (wchar_t *const dst, const wchar_t *const src) {
    const auto len = wcslen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = tolowerw(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

PCHAR MbsToLower (PCHAR const dst, const PCHAR const src) {
    const auto len = strlen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = tolower((uint8_t) src[i]);
    }

    dst[len] = 0x00;
    return dst;
}

size_t MbsToWcs (wchar_t *dst, const PCHAR src, const size_t length) {
	for (size_t i = 0; i < length; i++) {
		dst[i] = (wchar_t)src[i] | 0x00;
	}

	dst[length] = L'\0';
	return wcslen(dst);
}

size_t WcsToMbs (PCHAR const dst, const wchar_t *src, size_t length) {
	for (size_t i = 0; i < length; i++) {
		dst[i] = (char)(src[i] & 0xff);
	}

	dst[length * sizeof(wchar_t)] = '\0';
	return strlen(dst);
}

int EndsWithA (const PCHAR string, const PCHAR const end) {
    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if (!string || !end) {
        return false;
    }

    length1 = strlen(string);
    length2 = strlen(end);

    if (length1 < length2) {
        return false;
    }
    string = &string[length1 - length2];
    return strcmp(string, end) == 0;
}

int EndsWithW (const wchar_t *string, const wchar_t *const end) {
    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if ( !string || !end ) {
        return false;
    }

    length1 = wcslen(string);
    length2 = wcslen(end);

    if ( length1 < length2 ) {
        return false;
    }

    string = &string[ length1 - length2 ];
    return wcscmp(string, end) == 0;
}

size_t Span (const PCHAR s, const PCHAR accept) {
    int a = 1;
    int i;

    size_t offset = 0;

    while (a && *s) {
        for (a = i = 0; !a && i < strlen(accept); i++) {
            if (*s == accept[i]) {
                a = 1;
            }
        }

        if (a) {
            offset++;
        }
        s++;
    }

    return offset;
}

PCHAR StrChr (const PCHAR str, int c) {
    while (*str) {
        if (*str == (char)c) {
            return (PCHAR) str;
        }
        str++;
    }

    if (c == 0) {
        return (PCHAR)str;
    }

    return nullptr;
}

PCHAR StrTok (PCHAR str, const PCHAR delim) {
    static PCHAR saved          = { };
    char        *token_start    = { };
    char        *token_end      = { };

    if (str) { saved = str; }
    token_start = saved;

    if (!token_start) {
        saved = nullptr;
        return nullptr;
    }

    while (*token_start && strchr(delim, *token_start)) {
        token_start++;
    }

    token_end = token_start;
    while (*token_end && !strchr(delim, *token_end)) {
        token_end++;
    }

    if (*token_end) {
        *token_end  = 0;
        saved       = token_end + 1;
    }
    else {
        saved = nullptr;
    }

    return token_start;
}

PCHAR StrDup (_In_ const PCHAR str) {
    PCHAR   str2      = { };
    size_t  length  = 0;

    length  = strlen(str);
    str2    = (PCHAR)HeapAlloc(GetProcessHeap(), 0, length + 1);

    if (!str2) {
        return nullptr;
    }

    memcpy(str2, str, length + 1);
    return str2;
}

PCHAR* SplitNew (_In_ const PCHAR str, _In_ const PCHAR delim, _In_ INT* count) {
    PCHAR *result   = { };
    PCHAR *temp_res = { };

    PCHAR temp      = { };
    PCHAR token     = { };

    int size    = 2;
    int index   = 0;

    if (!(temp = strdup(str)) ||
        !(result = (PCHAR*)HeapAlloc(GetProcessHeap(), 0, size * sizeof(PCHAR ))) ||
        !(token = strtok(temp, delim))) {
        return nullptr;
    }

    while (token) {
        if (index > size) {
            size    += 1;
            temp_res = (PCHAR*) HeapReAlloc(GetProcessHeap(), 0, result, size * sizeof(PCHAR));

            if (!temp_res) {
                HeapFree(GetProcessHeap(), 0, result);
                result = nullptr;
                goto defer;
            }

            result = temp_res;
        }

        result[index] = strdup(token);

        if (!result[index]) {
            for (auto i = 0; i < index; i++) {
                HeapFree(GetProcessHeap(), 0, result[i]);
            }

            HeapFree(GetProcessHeap(), 0, result);
            result = nullptr;

            goto defer;
        }

        index++;
        token = strtok(0, delim);
    }

    *count = index;
    result[index] = 0;

defer:
    HeapFree(GetProcessHeap(), 0, temp);
    return result;
}

void SplitFree (PCHAR* split, int count) {
    for (auto i = 0; i < count; i++) {
        HeapFree(GetProcessHeap(), 0, split[i]);
    }

    HeapFree(GetProcessHeap(), 0, split);
}

void Trim (PCHAR str, char delim) {
    for (auto i = 0; str[i]; i++) {
        if (str[i] == delim) {
            str[i] = 0;
        }
    }
}

BOOL StringChar (const PCHAR string, const char symbol, size_t length) {
    for (auto i = 0; i < length - 1; i++) {
        if (string[i] == symbol) {
            return true;
        }
    }

    return false;
}
#endif // STDLIB_HPP
