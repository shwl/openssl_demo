#include "FileTools.h"
#include <fstream>
using namespace std;

long WriteDataToFile(const char* data, long dataLen /* = -1 */, const char* fileName /* = nullptr */)
{
	bool bFlag = false;
	long lRes = 0;
	if (!fileName)
	{
		fileName = "c:\\filetools.log";
		bFlag = true;
	}

	ios_base::openmode _Mode = ios::out | ios::binary | ios::ate;
	if (bFlag){
		_Mode = ios::out | ios::binary | ios::app;
	}
	fstream writeFile;
	writeFile.open(fileName, _Mode);
	if (!writeFile.is_open()){
		lRes = 403;
	}

	if (0 == lRes)
	{
		dataLen = (-1 == dataLen) ? strlen(data) : dataLen;
		writeFile.write(data, dataLen);
		if (bFlag){
			writeFile.write("\r\n", 2);
		}
		writeFile.close();
	}

	return lRes;
}

string ReadFile(const char* fileName)
{
	string data;
	fstream readFile;
	char buf[1024] = {};
	long len = _countof(buf);
	readFile.open(fileName, ios::in | ios::binary);
	if (readFile.is_open())
	{
		while (!readFile.eof())
		{
			readFile.read(buf, len);
			streamsize readLen = readFile.gcount();
			data.append(buf, readLen);
		}

		readFile.close();
	}

	return data;
}