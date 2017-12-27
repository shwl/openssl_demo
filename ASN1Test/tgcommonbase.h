#ifndef TGCOMMONBASE_H
#define TGCOMMONBASE_H

#ifndef WIN32
typedef long                LONG;
typedef unsigned int        ULONG;
typedef unsigned int        DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        UINT;
typedef wchar_t             WCHAR;

typedef void*               HWND;
typedef void*               HMODULE;
typedef char                CHAR;

typedef char*               BSTR;

#ifdef UNICODE
typedef wchar_t             TCHAR;
#else
typedef char                TCHAR;
#endif

#define _TRUNCATE           0xFFFFFFFF
#define MAX_PATH            260
#define INFINITE            0xFFFFFFFF


#define _stricmp            strcasecmp
#define _wcsicmp            wcscasecmp
#define _strnicmp           strncasecmp
#define _wcsnicmp           wcsncasecmp


#define CP_ACP              0
#define CP_UTF8             65001


#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef NULL
#define NULL                0
#endif

#ifndef WINAPI
#define WINAPI
#endif

#ifndef GetProcAddress
#define GetProcAddress      dlsym
#endif

#ifndef FARPROC
#define FARPROC void*
#endif




#ifndef tgmax
#define tgmax(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef tgmin
#define tgmin(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#endif

#ifndef QMESSAGEBOX_H
enum StandardButton {
    // keep this in sync with QDialogButtonBox::StandardButton and QPlatformDialogHelper::StandardButton
    NoButton           = 0x00000000,
    Ok                 = 0x00000400,
    Save               = 0x00000800,
    SaveAll            = 0x00001000,
    Open               = 0x00002000,
    Yes                = 0x00004000,
    YesToAll           = 0x00008000,
    No                 = 0x00010000,
    NoToAll            = 0x00020000,
    Abort              = 0x00040000,
    Retry              = 0x00080000,
    Ignore             = 0x00100000,
    Close              = 0x00200000,
    Cancel             = 0x00400000,
    Discard            = 0x00800000,
    Help               = 0x01000000,
    Apply              = 0x02000000,
    Reset              = 0x04000000,
    RestoreDefaults    = 0x08000000,

    FirstButton        = Ok,                // internal
    LastButton         = RestoreDefaults,   // internal

    YesAll             = YesToAll,          // obsolete
    NoAll              = NoToAll,           // obsolete

    Default            = 0x00000100,        // obsolete
    Escape             = 0x00000200,        // obsolete
    FlagMask           = 0x00000300,        // obsolete
    ButtonMask         = ~FlagMask          // obsolete
};
#endif

enum TGUIMessageType{
    _information = 1,
    _critical,
    _warning,
    _question,
    _about,
};

#define SM2SIGNVALUE_MAX_LEN   256     //SM2签名结果最大长度;
#define DIGESTVALUE_MAX_LEN    64      //摘要结果最大长度;

#endif // TGCOMMONBASE_H
