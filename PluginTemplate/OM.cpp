
#include "OM.h"
#define PAGESIZE  4096

/*
Función: GetMainThreadId
Descripción:
Funcion para obtener el ThreadId del thread principal de un proceso.

Parametros:
thread_id           - Variable de salida

Retorno:
TRUE o FALSE en funcion del exito de la funcion y en caso positivo
devolvemos el id en la variable de entrada

*/
BOOL GetMainThreadId(DWORD * thread_id)
{
	// Variables locales
	HANDLE        hThreadSnap;
	THREADENTRY32 th32;
	BOOL          return_function;
	DWORD         process_id;

	// Inicializacion de las variables
	process_id = GetCurrentProcessId();
	hThreadSnap = INVALID_HANDLE_VALUE;
	return_function = FALSE;

	// Obtenemos un SnapShot de todos los hilos del sistema
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		 
		return FALSE;
	}

	// Buscamos el primer hilo creado en nuestro proceso
	th32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &th32))
		;//	ShowGetLastErrorString("GetMainThreadId() - Thread32First()");

	do
	{
		if (th32.th32OwnerProcessID == process_id)
		{
			*thread_id = th32.th32ThreadID;
			return_function = TRUE;
		}

	} while (Thread32Next(hThreadSnap, &th32) && return_function != TRUE);

	// Cerramos el manejador del Snapshot
	CloseHandle(hThreadSnap);

	return return_function;
}

void OutputLog(const WCHAR* msg) {
	int len = wcslen(msg);
	WCHAR* final_msg = new WCHAR[len + 100];
	memset(final_msg, 0, 2 * (len + 100));

	wsprintfW(final_msg, L"[beatqq]%s", msg);
	OutputDebugStringW(final_msg);
	delete [] final_msg;
}

#define MAX_BUFF 2048
void OutputLogA(const char* msg) {
	int len = strlen(msg);
	char final_msg[MAX_BUFF] = { 0 };
	memset(final_msg, 0, MAX_BUFF);

	sprintf_s(final_msg, MAX_BUFF, "[beatqq]%s", msg);
	OutputDebugStringA(final_msg);
	//delete [] final_msg;
}

void PrintDebugW(const wchar_t *strOutputString, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, strOutputString);
	size_t nLen = _vscwprintf(strOutputString, vlArgs) + 1;
	wchar_t *strBuffer = new wchar_t[nLen];
	_vsnwprintf_s(strBuffer, nLen, nLen, strOutputString, vlArgs);
	va_end(vlArgs);
	//OutputDebugStringW(strBuffer);
	OutputLog(strBuffer);
	delete[] strBuffer;
}

void PrintDebugA(const char *strOutputString, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, strOutputString);
	size_t nLen = _vscprintf(strOutputString, vlArgs) + 1;
	char *strBuffer = new char[nLen];
	//char strBuffer[MAX_BUFF] = { 0 };
	_vsnprintf_s(strBuffer, nLen, nLen, strOutputString, vlArgs);
	va_end(vlArgs);
	//OutputDebugStringA(strBuffer);
	OutputLogA(strBuffer);
	delete[] strBuffer;
}

wstring AsciiToUnicode(const string& str) {
	// 预算-缓冲区中宽字节的长度  
	int unicodeLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
	// 给指向缓冲区的指针变量分配内存  
	wchar_t *pUnicode = (wchar_t*)malloc(sizeof(wchar_t)*unicodeLen);
	// 开始向缓冲区转换字节  
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, pUnicode, unicodeLen);
	wstring ret_str = pUnicode;
	free(pUnicode);
	return ret_str;
}
string	UnicodeToAscii(const wstring& wstr) {
	// 预算-缓冲区中多字节的长度  
	int ansiiLen = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	// 给指向缓冲区的指针变量分配内存  
	char *pAssii = (char*)malloc(sizeof(char)*ansiiLen);
	// 开始向缓冲区转换字节  
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, pAssii, ansiiLen, nullptr, nullptr);
	string ret_str = pAssii;
	free(pAssii);
	return ret_str;
}
wstring Utf8ToUnicode(const string& str) {
	// 预算-缓冲区中宽字节的长度  
	int unicodeLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
	// 给指向缓冲区的指针变量分配内存  
	wchar_t *pUnicode = (wchar_t*)malloc(sizeof(wchar_t)*unicodeLen);
	// 开始向缓冲区转换字节  
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, pUnicode, unicodeLen);
	wstring ret_str = pUnicode;
	free(pUnicode);
	return ret_str;
}
string	UnicodeToUtf8(const wstring& wstr) {
	// 预算-缓冲区中多字节的长度  
	int ansiiLen = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	// 给指向缓冲区的指针变量分配内存  
	char *pAssii = (char*)malloc(sizeof(char)*ansiiLen);
	// 开始向缓冲区转换字节  
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, pAssii, ansiiLen, nullptr, nullptr);
	string ret_str = pAssii;
	free(pAssii);
	return ret_str;
}
string	AsciiToUtf8(const string& str) {
	return UnicodeToUtf8(AsciiToUnicode(str));
}
string	Utf8ToAscii(const string& str) {
	return UnicodeToAscii(Utf8ToUnicode(str));
}

int		split(const string &str, vector<string>&svec, const string &sep)
{
	string::size_type beg = 0, end = 0;
	beg = str.find_first_not_of(sep, end);
	while (beg != string::npos) {
		end = str.find_first_of(sep, beg);
		if (end == string::npos) {
			svec.push_back(string(str, beg));
			break;
		}
		else {
			svec.push_back(string(str, beg, end - beg));
			beg = str.find_first_not_of(sep, end);
		}
	}

	return svec.size();
}

BOOL	GetProcessModulesList(DWORD dwPID, OUT vector<MODULEENTRY32> &moduleArr)
{
	moduleArr.clear();
	BOOL bRet = FALSE;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	//  Take a snapshot of all modules in the specified process. 
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap != INVALID_HANDLE_VALUE)
	{
		//  Set the size of the structure before using it. 
		me32.dwSize = sizeof(MODULEENTRY32);

		//  Retrieve information about the first module, 
		//  and exit if unsuccessful 
		if (Module32First(hModuleSnap, &me32))
		{
			//  Now walk the module list of the process, 
			//  and display information about each module 
			do
			{
				moduleArr.push_back(me32);
				PrintDebugW(L"/n/n   MODULE NAME:     %s", me32.szModule);
				PrintDebugW(L"/n     executable     = %s", me32.szExePath);
				PrintDebugW(L"/n     process ID     = 0x%p", me32.th32ProcessID);
				PrintDebugW(L"/n     ref count (g)  =     0x%04X", me32.GlblcntUsage);
				PrintDebugW(L"/n     ref count (p)  =     0x%04X", me32.ProccntUsage);
				PrintDebugW(L"/n     base address   = 0x%p", (DWORD)me32.modBaseAddr);
				PrintDebugW(L"/n     base size      = %d", me32.modBaseSize);

			} while (Module32Next(hModuleSnap, &me32));

			bRet = TRUE;
		}
		else
		{
			PrintDebugW(L"Module32First error");  // Show cause of failure 
		}
		//  Do not forget to clean up the snapshot object. 
		CloseHandle(hModuleSnap);
	}
	else
	{
		PrintDebugW(L"CreateToolhelp32Snapshot (of modules %d)", dwPID);
	}
	return(bRet);
}

DWORD	GetModuleLen(HMODULE hModule)
{
	PBYTE pImage = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeader;
	pImageDosHeader = (PIMAGE_DOS_HEADER)pImage;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	pImageNtHeader = (PIMAGE_NT_HEADERS)&pImage[pImageDosHeader->e_lfanew];
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}
	return pImageNtHeader->OptionalHeader.SizeOfImage;
}

/* 函数说明：查找特征码
/* markCode: 特征码字符串,不能有空格
/* distinct：特征码首地址离目标地址的距离 负数在特征码在上
/* size: 设置返回数据为几个BYTE 1 2 3 4
/* ordinal: 特征码出现的次数
/* beginAddr: 开始搜索地址
/* endAddr: 结束地址
/* offset: 返回目标地址
/* ret:返回目标地址的内容
/************************************************************************/
ULONG_PTR ScanOpcode(const char* szModName, const char *markCode, int distinct, int size, int ordinal, OUT PULONG_PTR offset, OUT  LPVOID addrContent)
{
	ULONG_PTR beginAddr = NULL;
	ULONG_PTR endAddr = NULL;

	while (true)
	{
		Sleep(1000);
		HMODULE hmod = GetModuleHandleA(szModName);

		if (hmod)
		{
			ULONG_PTR uLen = GetModuleLen(hmod);
			beginAddr = (ULONG_PTR)hmod;
			endAddr = beginAddr + uLen;
			break;
		}

	}

	//vector<MODULEENTRY32> moduleArr;
	//GetProcessModulesList(GetCurrentProcessId(), moduleArr);
	//for (size_t i = 0; i < moduleArr.size(); i++)
	//{
	//	if (wcsicmp(TEXT("steamui.dll"), moduleArr[i].szModule) == 0)
	//	{
	//		beginAddr = (ULONG_PTR)moduleArr[i].modBaseAddr;
	//		endAddr = beginAddr + moduleArr[i].modBaseSize;
	//		break;
	//	}
	//}


	//特征码长度
	int len = strlen(markCode) / 2;
	//将特征码转换成byte型
	BYTE *m_code = new BYTE[len];
	ZeroMemory(m_code, len);
	for (int i = 0; i < len; i++)
	{
		char c[] = { markCode[i * 2], markCode[i * 2 + 1], '\0' };
		if (strcmp(c, "??") == 0)
		{
			m_code[i] = '?';
			continue;
		}
		m_code[i] = (BYTE)::strtol(c, NULL, 16);
	}

	/////////////////////////查找特征码/////////////////////
	BOOL _break = FALSE;
	//用来保存在第几页中的第几个找到的特征码
	int curPage = 0;
	int curIndex = 0;
	//每页读取4096个字节
	BYTE *page = new BYTE[PAGESIZE + len - 1];
	ZeroMemory(page, PAGESIZE + len - 1);
	ULONG_PTR tmpAddr = beginAddr;
	ULONG_PTR ord = 0;
	while (tmpAddr <= endAddr - len)
	{
		::ReadProcessMemory(GetCurrentProcess(), (LPCVOID)tmpAddr, page, PAGESIZE + len - 1, 0);
		//在该页中查找特征码
		for (int i = 0; i < PAGESIZE; i++)
		{
			for (int j = 0; j < len; j++)
			{
				//只要有一个与特征码对应不上则退出循环
				if (m_code[j] == '?')
				{
					continue;
				}
				else if (m_code[j] != page[i + j])break;
				//找到退出所有循环
				if (j == len - 1)
				{
					ord++;
					if (ord != ordinal)
						break;
					_break = TRUE;
					curIndex = i; // 特征码的首地址偏移
					break;
				}
			}
			if (_break) break;
		}
		if (_break) break;
		curPage++;
		tmpAddr += PAGESIZE;
	}
	// 一个也没找到
	if (tmpAddr > endAddr - len)
		return 0;
	// 生成目标地址
	ULONG_PTR offsetaddr = curPage * PAGESIZE + curIndex + beginAddr + distinct;
	if (offset != NULL) {
		*offset = offsetaddr;
	}
	// 返回地址内容	
	if (addrContent != NULL)
	{
		::ReadProcessMemory(GetCurrentProcess(), (LPVOID)offsetaddr, addrContent, size, 0);
	}
	//生成立即数
	PVOID Imme = new char[20];
	DWORD dwIretImme = 0;
	try
	{
		::ReadProcessMemory(GetCurrentProcess(), (LPVOID)offsetaddr, Imme, size, 0);
		Imme = ((PBYTE)Imme + (size - 4));
		memcpy(&dwIretImme, (PDWORD)Imme, 4);
	}
	catch (...)
	{

	}
	delete m_code;
	delete page;
	delete ((PBYTE)Imme - (size - 4));
	return dwIretImme;
}

char* FindSubMem(const char* lpBuffer, int bufferSize, const char* lpSubMem, int subMemSize) {
	char* lpResult = NULL;
	for (int i = 0; i < bufferSize; i++)
	{
		if ((bufferSize - i) <= subMemSize) {
			break;
		}
		else {
			if (memcmp(&lpBuffer[i], lpSubMem, subMemSize) == 0) {
				lpResult = (char*)&lpBuffer[i];
				break;
			}
		}
	}
	return lpResult;
}

bool GetSubMem(char* lpBuffer, int bufferSize, char* lpSub1Mem, int subMem1Size, char* lpSub2Mem, int subMem2Size, char* lpOutSubMem) {
	bool bResult = false;
	char* lpSub1Temp = NULL;
	char* lpSub2Temp = NULL;
	lpSub1Temp = FindSubMem(lpBuffer, bufferSize, lpSub1Mem, subMem1Size);
	if (lpSub1Temp) {
		lpSub2Temp = FindSubMem(lpSub1Temp, bufferSize - (unsigned int)(lpSub1Temp - lpBuffer), lpSub2Mem, subMem2Size);
		if (lpSub2Temp) {
			if (lpOutSubMem) {
				memcpy(lpOutSubMem, &lpSub1Temp[subMem1Size], (unsigned int)(lpSub2Temp - &lpSub1Temp[subMem1Size]));
				bResult = true;
			}
		}
	}
	return bResult;
}

bool GetSubString(string *lpString, const char* lpBegin, const char* lpEnd, string& strOutSubString) {
	bool bResult = false;
	int begin = lpString->find(lpBegin);
	if (begin >= 0) {
		int end = lpString->find(lpEnd, begin);
		if (end >= begin) {
			strOutSubString = lpString->substr(begin + strlen(lpBegin), end - (begin + strlen(lpBegin)));
			bResult = true;
		}
	}
	return bResult;
}

bool InsertSubString(string *lpString, const char* lpSubStr, char* lpInsertStr, bool bIsBegin) {
	bool bResult = false;
	int insert = lpString->find(lpSubStr);
	if (insert >= 0) {
		if (bIsBegin) {
			lpString->insert(insert, lpInsertStr);
		}
		else {
			lpString->insert(insert + strlen(lpSubStr), lpInsertStr);
		}
		bResult = true;
	}
	return bResult;
}

bool ReplaceString(string *lpString, const char* lpBegin, const char* lpEnd, char* lpReplaceString, bool bIsBegin) {
	bool bResult = false;
	int begin = lpString->find(lpBegin);
	if (begin >= 0) {
		int end = lpString->find(lpEnd, begin + strlen(lpBegin));
		if (end >= begin) {
			if (bIsBegin) {
				lpString->replace(begin, end - begin, lpReplaceString);
			}
			else {
				lpString->replace(begin + strlen(lpBegin), end - (begin + strlen(lpBegin)), lpReplaceString);
			}

			bResult = true;
		}
	}
	return bResult;
}

BOOL	ImproveProcPriv()
{
	HANDLE token;
	//提升权限  
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		MessageBoxA(NULL, "打开进程令牌失败...", "错误", MB_ICONSTOP);
		return FALSE;
	}
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		MessageBoxA(NULL, "调整令牌权限失败...", "错误", MB_ICONSTOP);
		return FALSE;
	}
	CloseHandle(token);
	return TRUE;
}


//判断是否是x64进程
//参  数:进程句柄
//返回值:是x64进程返回TRUE,否则返回FALSE
BOOL	IsWow64ProcessEx(HANDLE hProcess)
{
	///*判断ntdll中的导出函数,可知是否是64位OS*/
	//HMODULE hMod = GetModuleHandle(TEXT("ntdll.dll"));
	//FARPROC x64fun = ::GetProcAddress(hMod, "ZwWow64ReadVirtualMemory64");
	//if (!x64fun) return FALSE;

	/*利用IsWow64Process判断是否是x64进程*/
	typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE, PBOOL);
	pfnIsWow64Process fnIsWow64Process = NULL;

	HMODULE hMod = GetModuleHandle(TEXT("kernel32.dll"));
	fnIsWow64Process = (pfnIsWow64Process)GetProcAddress(hMod, "IsWow64Process");
	if (!fnIsWow64Process) return FALSE;				//如果没有导出则判定为32位

	BOOL bX64;
	if (!fnIsWow64Process(hProcess, &bX64)) return FALSE;

	return !bX64;
}

int		GetProcessIsWOW64(HANDLE hProcess)
{
	int nRet = -1;
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	BOOL bRet;
	DWORD nError;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
	if (NULL != fnIsWow64Process)
	{
		bRet = fnIsWow64Process(hProcess, &bIsWow64);
		if (bRet == 0)
		{
			nError = GetLastError();
			nRet = -2;
		}
		else
		{
			if (bIsWow64)
			{
				nRet = 0;
			}
			else
			{
				nRet = 1;
			}
		}
	}
	return nRet;
}


/*从字符串的右边截取n个字符*/
wchar_t* right(wchar_t* dst, wchar_t*src, int n)
{
	wchar_t*p = src;
	wchar_t*q = dst;
	int len = wcslen(src);
	if (n>len) n = len;
	p += (len - n);   /*从右边第n个字符开始，到0结束，很巧啊*/
	while (*(q++) = *(p++));
	return dst;
}


PBYTE	MemShare::SetMemOffset(DWORD dwOffset)
{
	m_lpMapViewOffset = m_lpMapView;
	m_lpMapViewOffset += dwOffset;
	return m_lpMapViewOffset;
}

PBYTE	MemShare::WriteShareMem(PBYTE bContent, DWORD dwSize, DWORD dwOffset)
{
	CopyMemory(m_lpMapViewOffset, bContent, dwSize);
	m_lpMapViewOffset += dwOffset;
	return m_lpMapViewOffset;
}
PBYTE   MemShare::ReadShareMem(DWORD dwSize, OUT PBYTE bOutBuf)
{
	//m_lpMapViewOffset += dwOffset;
	CopyMemory(bOutBuf, m_lpMapViewOffset, dwSize);
	return m_lpMapViewOffset;
}
PBYTE   MemShare::ReadShareMemToOffset(DWORD dwSize, OUT PBYTE bOutBuf)
{
	//m_lpMapViewOffset += dwOffset;
	CopyMemory(bOutBuf, m_lpMapViewOffset, dwSize);
	m_lpMapViewOffset += dwSize;
	return m_lpMapViewOffset;
}

PBYTE   MemShare::GetMapView()
{
	UnmapViewOfFile(m_lpMapView);
	m_lpMapView = (PBYTE)MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	m_lpMapViewOffset = m_lpMapView;
	return m_lpMapViewOffset;
}
void	MemShare::UnMapView()
{
	UnmapViewOfFile(m_lpMapView);
}
void	MemShare::CloseShareMap()
{
	UnMapView();
	CloseHandle(m_hMapFile);
}


MyEvent::MyEvent()
{

}
MyEvent::MyEvent(const TCHAR* szEventName) 
{
	m_Event = OpenEvent(EVENT_ALL_ACCESS, FALSE, szEventName);
	if (!m_Event)
	{
		m_Event = CreateEvent(NULL, FALSE, FALSE, szEventName);
	}
}
MyEvent::~MyEvent()
{
}
HANDLE MyEvent::Init(const TCHAR* szEventName)
{
	m_Event = OpenEvent(EVENT_ALL_ACCESS, FALSE, szEventName);
	if (!m_Event)
	{
		m_Event = CreateEvent(NULL, FALSE, FALSE, szEventName);
	}
	return m_Event;
}
void MyEvent::WaitEvent()
{
	//if (m_Event)
	WaitForSingleObject(m_Event, 2000);
}
void MyEvent::SetMyEvent()
{
	if (m_Event)
		SetEvent(m_Event);
}