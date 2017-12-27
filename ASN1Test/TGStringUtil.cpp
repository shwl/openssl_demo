#include "TGStringUtil.h"
#include <algorithm>
#include <stdio.h>
#include <stddef.h>

namespace tgstr
{
	template <typename T>
	std::vector<T> tgsplit(const T& src, const T& delimit, bool isRemoveRepeat)
	{
		std::vector<T> vResult;
		if (src.empty() || delimit.empty())
			return vResult;

        long deli_len = delimit.length();
		long index = 0, last_search_position = 0;
		while ((index = src.find(delimit, last_search_position)) != T::npos)
		{
			if (index != last_search_position)
			{
				T tmp = src.substr(last_search_position, index - last_search_position);
                if (!isRemoveRepeat || vResult.end() == find(vResult.begin(), vResult.end(), tmp)){
					vResult.push_back(tmp);
				}
			}
			last_search_position = index + deli_len;
		}

		T last_one = src.substr(last_search_position);
		if (!last_one.empty() && vResult.end() == find(vResult.begin(), vResult.end(), last_one)){
			vResult.push_back(last_one);
		}

		return vResult;
	}

	std::vector<std::string> split(const std::string& src, const std::string& delimit, bool isRemoveRepeat /* = false */)
	{
		return tgsplit(src, delimit, isRemoveRepeat);
	}

	std::vector<std::wstring> split(const std::wstring& src, const std::wstring& delimit, bool isRemoveRepeat /* = false */)
	{
		return tgsplit(src, delimit, isRemoveRepeat);
	}

    char* copy(const char* src, long srcLen)
	{
		if (!src){
            return NULL;
		}
        int len = (-1 == srcLen) ? strlen(src) + 1 : srcLen;
		char* p = new char[len];
        memset(p, 0, len);
        memcpy(p, src, len);
		return p;
	}

    bool copy(char* pDesp, ULONG* pulDespLen, const char* srcData, long srcDataLen/* = -1*/)
	{
		bool bRes = false;
        ULONG len = (-1 == srcDataLen) ? strlen(srcData) :  srcDataLen;
        if (*pulDespLen >= len)
		{
            memset(pDesp, 0, *pulDespLen);
            memcpy(pDesp, srcData, len);
			bRes = true;
		}
        *pulDespLen = len;
		return bRes;
	}

    bool copy(wchar_t* pDesp, ULONG* pulDespLen, const wchar_t* srcData, long srcDataLen/* = -1*/)
	{
		bool bRes = false;
        ULONG len = (-1 == srcDataLen) ? wcslen(srcData) : srcDataLen;
		if (*pulDespLen > len)
		{
            wcscpy(pDesp, srcData);
			bRes = true;
		}
		*pulDespLen = len + 1;
		return bRes;
	}

    /* Convert binary data in <buf> of size <len> to a hex-encoded string */
    char *MemToHex(const unsigned char *buf, int len)
    {
        /* 2 hex chars per byte, +1 for terminating 0 */
        char *ret = (char*)malloc(2 * (size_t)len + 1);
        if (!ret)
            return NULL;
        for (int i = 0; i < len; i++)
            sprintf(ret + 2 * i, "%02x", *buf++);
        ret[2 * len] = '\0';
        return ret;
    }

    /* Reverse of MemToHex. Convert a 0-terminatd hex-encoded string <s> to
       binary data pointed by <buf> of max sisze bufLen.
       Returns false if size of <s> doesn't match <bufLen>. */
    bool HexToMem(const char *s, unsigned char *buf, int bufLen)
    {
        for (; bufLen > 0; bufLen--)
        {
            int c;
            if (1 != sscanf(s, "%02x", &c))
                return false;
            s += 2;
            *buf++ = (unsigned char)c;
        }
        return *s == '\0';
    }

    size_t get_wchar_size(const char *str)
    {
        size_t len = strlen(str);
        size_t size = 0;
        size_t i;
        for (i = 0; i < len; i++)
        {
            if (str[size] >= 0 && str[size] <= 127) //不是全角字符;
                size += sizeof(wchar_t);
            else //是全角字符，是中文;
            {
                size += sizeof(wchar_t);
                i += 2;
            }
        }
        return size;
    }

    char *ToMultiByte(const wchar_t *pw, const char* CodePage)
    {
        setlocale(LC_ALL, CodePage);

        if (!pw)
            return NULL;
        size_t size = wcslen(pw)*sizeof(wchar_t);
        char *pc;
        if (!(pc = (char*)malloc(size)))
        {
            return NULL;
        }
        wcstombs(pc, pw, size);
        return pc;
    }

    wchar_t *ToWideChar(const char *pc, const char* CodePage)
    {
        setlocale(LC_ALL, CodePage);

        if (!pc)
            return NULL;
        size_t size_of_ch = strlen(pc)*sizeof(char);
        size_t size_of_wc = get_wchar_size(pc);
        wchar_t *pw;
        if (!(pw = (wchar_t*)malloc(size_of_wc)))
        {
            return NULL;
        }
        mbstowcs(pw, pc, size_of_wc);
        return pw;
    }

    void to_lower(char *str)
    {
        int i = 0;
        while (str[i] != 0)
        {
            if ((str[i] >= 'A') && (str[i] <= 'Z'))
                str[i] += 32;
            i++;
        }
    }

    void to_upper(char *str)
    {
        int i = 0;
        while (str[i] != 0)
        {
            if ((str[i] >= 'a') && (str[i] <= 'z'))
                str[i] -= 32;
            i++;
        }
    }

    bool isequal(const char* str1, const char* str2)
    {
        bool bRes = false;
        if(0 < Len(str1) && 0 < Len(str2))
        {
            if(0 == strcmp(str1, str2)){
                bRes = true;
            }
        }
        return bRes;
    }

    int cmp(const char* str1, const char* str2, bool isIgnoreCase)
    {
        int nRes = 0;

        if(isIgnoreCase)
        {
            char* strTmp1 = tgstr::copy(str1);
            char* strTmp2 = tgstr::copy(str2);
            tgstr::to_lower((char*)strTmp1);
            tgstr::to_lower((char*)strTmp2);
            nRes = strcmp(strTmp1, strTmp2);
            delete strTmp1;
            delete strTmp2;
        }
        else
        {
            nRes = strcmp(str1, str2);
        }

        return nRes;
    }
}
