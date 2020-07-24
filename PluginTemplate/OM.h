#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
using namespace std;
BOOL GetProcessModulesList(DWORD dwPID, OUT vector<MODULEENTRY32> &moduleArr);
int		split(const string &str, vector<string>&svec, const string &sep);
ULONG_PTR ScanOpcode(const char* szModName, const char *markCode, int distinct, int size, int ordinal, OUT PULONG_PTR offset, OUT  LPVOID addrContent);

BOOL GetMainThreadId(DWORD * thread_id);
void	PrintDebugW(const wchar_t *strOutputString, ...);

void	PrintDebugA(const char *strOutputString, ...);

wstring AsciiToUnicode(const string& str);
string UnicodeToAscii(const wstring& wstr);
wstring Utf8ToUnicode(const string& str);
string UnicodeToUtf8(const wstring& wstr);
string AsciiToUtf8(const string& str);
string Utf8ToAscii(const string& str);

int decompressed(const char *at, size_t length, string& out);
int gz_compress(const char *src, int srcLen, char *dest, int destLen);
char* FindSubMem(const char* lpBuffer, int bufferSize, const char* lpSubMem, int subMemSize);

bool GetSubMem(char* lpBuffer, int bufferSize, char* lpSub1Mem, int subMem1Size, char* lpSub2Mem, int subMem2Size, char* lpOutSubMem);

bool GetSubString(string *lpString, const char* lpBegin, const char* lpEnd, string& strOutSubString);

bool InsertSubString(string *lpString, const char* lpSubStr, char* lpInsertStr, bool bIsBegin);

bool ReplaceString(string *lpString, const char* lpBegin, const char* lpEnd, char* lpReplaceString, bool bIsBegin);
BOOL	ImproveProcPriv();

BOOL	IsWow64ProcessEx(HANDLE hProcess);

int		GetProcessIsWOW64(HANDLE hProcess);

TCHAR*	right(TCHAR* dst, TCHAR *src, int n);

class MyEvent
{
public:
	MyEvent();
	MyEvent(const TCHAR* szEventName);
	~MyEvent();

	HANDLE	Init(const TCHAR* szEventName);
	void	WaitEvent();
	void	SetMyEvent();
private:
	HANDLE m_Event;
};
class MemShare
{
public:
	MemShare() :m_hMapFile(0), m_lpMapView(0), m_lpMapViewOffset(0)
	{
	}
	MemShare(const TCHAR* szMemName, DWORD dwSizeOfMem) : m_hMapFile(0), m_lpMapView(0), m_lpMapViewOffset(0)
	{
		m_hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szMemName);
		if (!m_hMapFile)
		{
			m_hMapFile = CreateFileMapping((HANDLE)-1, NULL, PAGE_READWRITE, 0, dwSizeOfMem, szMemName);
		}
		m_lpMapView = (PBYTE)MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		m_lpMapViewOffset = m_lpMapView;
	}

	~MemShare()
	{
	}
	//static  MemShare* GetInstance()
	//{
	//	if (m_pInstance == NULL)  //判断是否第一次调用
	//		m_pInstance = new MemShare();
	//	return m_pInstance;
	//}

	PBYTE	SetMemOffset(DWORD dwOffset);
	PBYTE	WriteShareMem(PBYTE bContent, DWORD dwSize, DWORD dwOffset);
	PBYTE	ReadShareMem(DWORD dwSize, OUT PBYTE bOutBuf);
	PBYTE	ReadShareMemToOffset(DWORD dwSize, OUT PBYTE bOutBuf);
	void	UnMapView();
	void	CloseShareMap();
	PBYTE   GetMapView();

private:

	HANDLE	m_hMapFile;
	PBYTE	m_lpMapView;
	PBYTE	m_lpMapViewOffset;
	//static  MemShare* m_pInstance;
};


