#include "VSTriage.h"

extern PNODE pnReportHead; // global variable - pointer to head node.

int cmp(const void* a, const void* b)
{
	const wchar_t** ia = (const wchar_t**)a;
	const wchar_t** ib = (const wchar_t**)b;
	if ((wcslen(*ia) > 0) && (wcslen(*ib) > 0))
	{
		if ((*ia[0] == L'\t') && (*ib[0] != L'\t'))
		{
			return 1;
		}
		if ((*ia[0] != L'\t') && (*ib[0] == L'\t'))
		{
			return -1;
		}
	}
	return _wcsicmp(*ia, *ib);
}

VOID SortUniqueMultilineWchar(PWSTR pwszStringToSort, PWSTR* pwszSortedString)
{
	PWSTR* ppwstrLines;
	DWORD dwCurrentLineNumber = 0;
	wchar_t* wcToken;
	wchar_t* next_token = NULL;
	wchar_t seps[] = L"\r\n";
	PWSTR pwszNewString;
	size_t stStringSizeBytes;
	DWORD dwMaxLines = SIZE_1KB;

	stStringSizeBytes = LocalSize(pwszStringToSort);

	CRASHORALLOC(ppwstrLines, sizeof(PWSTR) * dwMaxLines);
	CRASHORALLOC(pwszNewString, stStringSizeBytes);

	wcToken = wcstok_s(pwszStringToSort, seps, &next_token);

	while (NULL != wcToken)
	{
		ppwstrLines[dwCurrentLineNumber++] = wcToken;
		wcToken = wcstok_s(NULL, seps, &next_token);
		if (dwCurrentLineNumber == dwMaxLines)
		{
			//too many lines. reallocate
			PWSTR* ppwstrNewLines;
			dwMaxLines = 2 * dwMaxLines;
			ALLOCORCRASH(ppwstrNewLines, sizeof(PWSTR) * dwMaxLines);
			memcpy_s(ppwstrNewLines, LocalSize(ppwstrNewLines), ppwstrLines, LocalSize(ppwstrLines));
			LocalFree(ppwstrLines);
			ppwstrLines = ppwstrNewLines;
		}
	}

	if (dwCurrentLineNumber < 2) //no touch
	{
		LocalFree(ppwstrLines);
		wmemcpy_s(pwszNewString, stStringSizeBytes / sizeof(WCHAR), pwszStringToSort, wcslen(pwszStringToSort));
		if (1 == dwCurrentLineNumber)
		{
			StringCchCatW(pwszNewString, stStringSizeBytes / sizeof(WCHAR), L"\r\n");
		}
		*pwszSortedString = pwszNewString;
		return;
	}

	qsort(ppwstrLines, dwCurrentLineNumber, sizeof(PWSTR), cmp);

	// add line 0
	StringCchCatW(pwszNewString, stStringSizeBytes / sizeof(WCHAR), ppwstrLines[0]);
	StringCchCatW(pwszNewString, stStringSizeBytes / sizeof(WCHAR), L"\r\n");

	// add lines from 1, if != previous.
	for (DWORD i = 1; i < dwCurrentLineNumber; i++)
	{
		if (0 != _wcsicmp(ppwstrLines[i - 1], ppwstrLines[i]))
		{
			StringCchCatW(pwszNewString, stStringSizeBytes / sizeof(WCHAR), ppwstrLines[i]);
			StringCchCatW(pwszNewString, stStringSizeBytes / sizeof(WCHAR), L"\r\n");
		}
	}

	*pwszSortedString = pwszNewString;
	LocalFree(ppwstrLines);
}


VOID ResizeWcharBufIfNeeded(PWSTR* pwszBuffer, size_t* pstBufferSizeBytes)
{
	//check if we have 50% of buffer. If yes - double the buffer.
	if (wcslen(*pwszBuffer) > *pstBufferSizeBytes / (2 * sizeof(WCHAR)))
	{
		PWSTR buf2;
		*pstBufferSizeBytes *= 2;
		buf2 = LocalAlloc(LPTR, *pstBufferSizeBytes);
		CRASHIFNULLALLOC(buf2);
		wmemcpy_s(buf2, wcslen(*pwszBuffer), *pwszBuffer, wcslen(*pwszBuffer));
		LocalFree(*pwszBuffer);
		*pwszBuffer = buf2;
	}
}

VOID ShrinkWcharBuffer(PWSTR* pwszBuffer)
{
	if (NULL == pwszBuffer)
	{
		return; //nothing to do
	}

	PWSTR buf1;
	size_t stLenWchars;
	size_t stMaxLenBytes;

	stMaxLenBytes = LocalSize(*pwszBuffer);
	stLenWchars = wcsnlen(*pwszBuffer, stMaxLenBytes / sizeof(WCHAR));

	buf1 = LocalAlloc(LPTR, stLenWchars * sizeof(WCHAR) + 2);
	CRASHIFNULLALLOC(buf1);

	if (stLenWchars > 0)
	{
		errno_t iRet;
		iRet = wmemcpy_s(buf1, stLenWchars + 1, *pwszBuffer, stLenWchars);
		if (iRet)
		//cannot copy for some reason. the best thing is to return original buffer. It wastes the memory but works.
		{
			LocalFree(buf1);
			return;
		}
	}
	LocalFree(*pwszBuffer);
	*pwszBuffer = buf1;
}

VOID AddCheckHeader(PWSTR pwszBuffer, size_t stBufferSizeBytes, PWSTR pwszHeaderContent, BOOL bStartWithCRLF)
{
	PWSTR pwszTimeStr;
	HRESULT hrStr;
	pwszTimeStr = GetCurrentTimeZ();
	if (bStartWithCRLF)
	{
		hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), L"\r\n\r\n");
		CHECKSTRINGHR(hrStr);
	}
	hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), L"====");
	CHECKSTRINGHR(hrStr);
	hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), pwszHeaderContent);
	CHECKSTRINGHR(hrStr);
	hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), L"==== ");
	CHECKSTRINGHR(hrStr);
	hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), pwszTimeStr);
	CHECKSTRINGHR(hrStr);
	hrStr = StringCchCatW(pwszBuffer, stBufferSizeBytes / sizeof(WCHAR), L"\r\n");
	CHECKSTRINGHR(hrStr);
	LocalFree(pwszTimeStr);
}

//Creates a new Node and returns pointer to it.
PNODE GetNewNode(PWSTR x)
{
	PNODE newNode;
	newNode = (PNODE)LocalAlloc(LPTR, sizeof(NODE));
	CRASHIFNULLALLOC(newNode);
	newNode->data = x;
	newNode->prev = NULL;
	newNode->next = NULL;
	return newNode;
}

//Inserts a Node at head of doubly linked list
VOID InsertAtHead(PWSTR x)
{
	PNODE newNode = GetNewNode(x);
	if (pnReportHead == NULL)
	{
		pnReportHead = newNode;
		return;
	}
	pnReportHead->prev = newNode;
	newNode->next = pnReportHead;
	pnReportHead = newNode;
}

//Inserts a Node at tail of Doubly linked list
VOID InsertAtOutputTail(PWSTR x)
{
	PNODE temp = pnReportHead;
	PNODE newNode = GetNewNode(x);
	if (pnReportHead == NULL)
	{
		pnReportHead = newNode;
		return;
	}
	while (temp->next != NULL)
	{
		temp = temp->next; // Go To last Node
	}
	temp->next = newNode;
	newNode->prev = temp;
}

//Prints all the elements in linked list in forward traversal order
VOID PrintOutput(void)
{
	PNODE temp = pnReportHead;
	wprintf(L"Forward: ");
	while (temp != NULL)
	{
		wprintf(L"%s ", temp->data);
		temp = temp->next;
	}
	wprintf(L"\r\n");
}

//Prints all elements in linked list in reverse traversal order.
VOID ReversePrint(void)
{
	PNODE temp = pnReportHead;
	if (temp == NULL)
	{
		return; // empty list, exit
	}
	// Going to last Node
	while (temp->next != NULL)
	{
		temp = temp->next;
	}
	// Traversing backward using prev pointer
	wprintf(L"Reverse: ");
	while (temp != NULL)
	{
		wprintf(L"%s ", temp->data);
		temp = temp->prev;
	}
	wprintf(L"\r\n");
}

//Enables all privileges present in the token, one by one.
VOID EnableAllPrivileges(void) //or at least try...
{
	HANDLE hToken;
	BOOL bStatus;
	DWORD dwLastError;
	DWORD dwTokenPrivilegeBytes;
	PTOKEN_PRIVILEGES pPrivs;
	DWORD i;
	WCHAR wszPrivilegeName[MAX_PRIVILEGE_NAME_LEN];
	DWORD dwLen;
	TOKEN_PRIVILEGES tp;


	bStatus = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (!bStatus)
	{
		dwLastError = GetLastError();
		wprintf(L"ERROR: OpenProcessToken() returned %u\r\n", dwLastError);
		return;
	}


	//get the token information size, check if not zero
	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwTokenPrivilegeBytes);
	if (0 == dwTokenPrivilegeBytes)
	{
		dwLastError = GetLastError();
		wprintf(L"ERROR: GetTokenInformation() can't obtain token size. Error %u\r\n", dwLastError);
		CloseHandle(hToken);
		return;
	}

	//allocate buffer for storing token information
	pPrivs = LocalAlloc(LPTR, dwTokenPrivilegeBytes);
	if (NULL == pPrivs)
	{
		wprintf(L"ERROR: Cannot allocate buffer.\r\n");
		CloseHandle(hToken);
		return;
	}

	//put the token data to the buffer
	bStatus = GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwTokenPrivilegeBytes, &dwTokenPrivilegeBytes);
	if (!bStatus)
	{
		dwLastError = GetLastError();
		wprintf(L"ERROR: GetTokenInformation() returned %u\r\n", dwLastError);
		CloseHandle(hToken);
		LocalFree(pPrivs);
		return;
	}

	//iterate through privileges
	//I can do it with one AdjustTokenPrivileges() call but iterating through an array allows me to display names and catch failed attempts.
	//the all-at-once  approach is nicely demonstrated at https://docs.microsoft.com/en-us/windows/win32/wmisdk/executing-privileged-operations-using-c- 
	for (i = 0; i < pPrivs->PrivilegeCount; i++)
	{
		//wprintf(L"Enabling privilege 0x%02x ", pPrivs->Privileges[i].Luid.LowPart);
		dwLen = MAX_PRIVILEGE_NAME_LEN;
		LookupPrivilegeNameW(NULL, &(pPrivs->Privileges[i].Luid), wszPrivilegeName, &dwLen);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = pPrivs->Privileges[i].Luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	}

	CloseHandle(hToken);
	LocalFree(pPrivs);
}

//LocalFree required
PWSTR SystemTimeToISO8601(SYSTEMTIME stTime)
{
	PWSTR pwszISOTimeZ;
	//2022-05-02T07:34:56Z
	//	GetSystemTime(&stTime);
	pwszISOTimeZ = LocalAlloc(LPTR, (ISO_TIME_LEN + 3) * sizeof(WCHAR));
	if (pwszISOTimeZ)
	{
		StringCchPrintfW(
			pwszISOTimeZ,
			ISO_TIME_LEN + 3,
			ISO_TIME_FORMAT_W,
			stTime.wYear,
			stTime.wMonth,
			stTime.wDay,
			stTime.wHour,
			stTime.wMinute,
			stTime.wSecond);
	}
	return pwszISOTimeZ;
}

//LocalFree required
PWSTR GetCurrentTimeZ(void)
{
	SYSTEMTIME stTime;
	GetSystemTime(&stTime);
	return (SystemTimeToISO8601(stTime));
}

BOOL KernelDump(PWSTR pwszDumpName)
{
	HANDLE hFile;
	NTSTATUS status;
	ULONG ulReturnLength;

	hFile = CreateFile(
		pwszDumpName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL
	);

	if (NULL == hFile)
	{
		wprintf(L"Error creating dump file: %i\r\n", GetLastError());
		return FALSE;
	}

	SYSDBG_LIVEDUMP_CONTROL slcDumpControl = {0};
	slcDumpControl.Version = 1;
	slcDumpControl.BugCheckCode = LIVE_SYSTEM_DUMP;
	slcDumpControl.DumpFileHandle = hFile;

	status = NtSystemDebugControl(SysDbgGetLiveKernelDump, &slcDumpControl, sizeof(slcDumpControl), NULL, 0, &ulReturnLength);
	if (STATUS_SUCCESS != status)
	{
		wprintf(L"Error writing dump: 0x%08x\r\n", status);
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}
