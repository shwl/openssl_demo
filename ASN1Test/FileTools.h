#ifndef _FILETOOLS_H_
#define _FILETOOLS_H_

#include <string>
using namespace std;

long WriteDataToFile(const char* data, long dataLen = -1, const char* fileName = nullptr);
string ReadFile(const char* fileName);

#endif
