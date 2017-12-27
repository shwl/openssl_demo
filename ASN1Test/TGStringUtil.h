#ifndef _TGStringUtil_H_
#define _TGStringUtil_H_

#include <string.h>
#include <string>
#include <vector>
#include <stdlib.h>
#include "tgcommonbase.h"

namespace tgstr
{
	//字符串分割;
    std::vector<std::string> split(const std::string& src, const std::string& delimit, bool isRemoveRepeat = false);
    std::vector<std::wstring> split(const std::wstring& src, const std::wstring& delimit, bool isRemoveRepeat = false);

    //字符串复制,需delete释放;
    char* copy(const char* src, long srcLen = -1);

    bool copy(char* pDesp, ULONG* pulDespLen, const char* srcData, long srcDataLen = -1);
    bool copy(wchar_t* pDesp, ULONG* pulDespLen, const wchar_t* srcData, long srcDataLen = -1);

    inline size_t Len(const char *s) { return s ? strlen(s) : 0; }
    inline size_t Len(const wchar_t *s) { return s ? wcslen(s) : 0; }

    char *  MemToHex(const unsigned char *buf, int len);
    bool    HexToMem(const char *s, unsigned char *buf, int bufLen);

    char *  ToMultiByte(const wchar_t *txt, const char* CodePage);
    wchar_t * ToWideChar(const char *src, const char* CodePage);

    inline wchar_t * FromAnsi(const char *src) { return ToWideChar(src, NULL); }
    inline char * ToAnsi(const wchar_t *src) { return ToMultiByte(src, NULL); }


    void to_lower(char *str);
    void to_upper(char *str);

    //字符串是否相等，如果为空，返回false;
    bool isequal(const char* str1, const char* str2);

    int cmp(const char* str1, const char* str2, bool isIgnoreCase = true);
};

#endif
