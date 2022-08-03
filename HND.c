#include "VSTriage.h"

PWSTR pwszHndBuf = NULL;
size_t stHndBufSize;

typedef struct _NameInfo
{
	OBJECT_NAME_INFORMATION Header;
	WCHAR Buffer[SIZE_1KB];
} NameInfo, *PNameInfo;

typedef struct _THS
{
	HANDLE HandleToQuery;
	NTSTATUS Status;
	NameInfo niNameInfo;
} THS, *PTHS;

DWORD WINAPI ThNtQueryObject(LPVOID lpParam)
{
	THS thsParam;
	memcpy(&thsParam, lpParam, sizeof(THS));

	((PTHS)lpParam)->Status = NtQueryObject(
		((PTHS)lpParam)->HandleToQuery,
		ObjectNameInformation,
		&(((PTHS)lpParam)->niNameInfo),
		sizeof(((PTHS)lpParam)->niNameInfo),
		NULL);
	return 0;
}


PSYSTEM_HANDLE_INFORMATION_EX HNDGetHandleInformation(void)
{
	NTSTATUS Status;
	PSYSTEM_HANDLE_INFORMATION_EX pLocAllHandleInfo = NULL;
	ULONG ulAllocatedHandleInfoSize = 0;
	ULONG ulRealHandleInfoSize = 0;

	do
	{
		Status = NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			pLocAllHandleInfo,
			ulAllocatedHandleInfoSize,
			&ulRealHandleInfoSize);
		if (STATUS_INFO_LENGTH_MISMATCH == Status)
		{
			if (pLocAllHandleInfo)
			{
				LocalFree(pLocAllHandleInfo);
			}
			ulAllocatedHandleInfoSize = ulRealHandleInfoSize + SIZE_1KB;
			//use returned value plus some space just in case.
			pLocAllHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)LocalAlloc(LPTR, ulAllocatedHandleInfoSize);
			CRASHIFNULLALLOC(pLocAllHandleInfo);
		}
	}
	while (STATUS_INFO_LENGTH_MISMATCH == Status);
	return pLocAllHandleInfo; //free by caller
}


BOOL HNDMain(void)
{
	PSYSTEM_HANDLE_INFORMATION_EX pAllHandleInfo;
	pAllHandleInfo = HNDGetHandleInformation(); //never null

	ULONG ulIndex;
	ULONG_PTR ulLastPid = ULONG_MAX;
	HANDLE hProcHandle = NULL;
	BOOL bRes;
	HANDLE hDuplicatedHandle;
	WCHAR wszLastPath[SIZE_1KB] = {0};

	PWSTR pwszTempBuf;
	DWORD dwTempBufBytes;
	dwTempBufBytes = SIZE_16MB;
	pwszTempBuf = LocalAlloc(LPTR, dwTempBufBytes);
	CRASHIFNULLALLOC(pwszTempBuf);

	for (ulIndex = 0; ulIndex < pAllHandleInfo->NumberOfHandles; ulIndex++)
	{
		WCHAR wszNameString[SIZE_1KB] = L"\0";
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* HandleEntry;

		HandleEntry = &(pAllHandleInfo->Handles[ulIndex]);

		if (ulLastPid != HandleEntry->UniqueProcessId) //new pid
		{
			wprintf(
				L"\r%*s\rListing Handles - PID: %llu        \b\b\b\b\b\b\b\b",
				BLANKS_TO_WRITE,
				L"\b",
				HandleEntry->UniqueProcessId);

			ResizeWcharBufIfNeeded(&pwszHndBuf, &stHndBufSize);

			if (hProcHandle)
			{
				CloseHandle(hProcHandle);
			}
			hProcHandle = OpenProcess(
				PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE,
				(DWORD)HandleEntry->UniqueProcessId);
			ulLastPid = HandleEntry->UniqueProcessId;

			WCHAR wszExeName[MAX_PATH] = L"(Cannot open process)";
			StringCchPrintfW(wszExeName, ARRAYSIZE(wszExeName), L"(ERROR: %i)", GetLastError());
			DWORD dwExeNameSize;
			if (hProcHandle)
			{
				dwExeNameSize = ARRAYSIZE(wszExeName);
				QueryFullProcessImageNameW(hProcHandle, 0, wszExeName, &dwExeNameSize);
			}

			PWSTR pwszSorted = NULL;
			SortUniqueMultilineWchar(pwszTempBuf, &pwszSorted);
			StringCchCatW(pwszHndBuf, stHndBufSize / sizeof(WCHAR), pwszSorted);
			LocalFree(pwszSorted);

			pwszTempBuf[0] = L'\0';
			StringCchPrintfW(wszNameString, SIZE_1KB, L"%d:\t%s\r\n", (DWORD)HandleEntry->UniqueProcessId, wszExeName);
			StringCchCatW(pwszTempBuf, dwTempBufBytes / sizeof(WCHAR), wszNameString);
		}
		if (!hProcHandle)
		{
			continue;
		}

		bRes = DuplicateHandle(
			hProcHandle,
			(HANDLE)HandleEntry->HandleValue,
			GetCurrentProcess(),
			&hDuplicatedHandle,
			0,
			FALSE,
			0);

		if (!bRes)
		{
			continue;
		}

		PTHS thsParam;
		thsParam = (PTHS)LocalAlloc(LPTR, sizeof(THS));
		CRASHIFNULLALLOC(thsParam);

		thsParam->HandleToQuery = hDuplicatedHandle;

		HANDLE hThNtQueryObjectHandle;

		hThNtQueryObjectHandle = CreateThread(
			NULL,
			0,
			ThNtQueryObject,
			thsParam,
			0,
			NULL
		);

		DWORD dwWso;
		dwWso = WaitForSingleObject(hThNtQueryObjectHandle, THREAD_TIMEOUT_MS);
		CloseHandle(hThNtQueryObjectHandle);

		if (WAIT_OBJECT_0 == dwWso)
		{
			if (S_OK == thsParam->Status)
			{
				if (thsParam->niNameInfo.Header.Name.Length != 0)
				{
					if (wcsstr(thsParam->niNameInfo.Buffer, L"\\BaseNamedObjects\\{") != thsParam->niNameInfo.Buffer)
					//useless noise
					{
						StringCchPrintfW(wszNameString, SIZE_1KB, L"\t%s\r\n", thsParam->niNameInfo.Buffer);
						if (0 != wcscmp(wszNameString, wszLastPath)) //non-duplicate
						{
							StringCchCatW(pwszTempBuf, dwTempBufBytes / sizeof(WCHAR), wszNameString);
							StringCchPrintfW(wszLastPath, SIZE_1KB, L"%s", wszNameString); // for detecting duplicates
							//						wprintf(L"%s\r\n", thsParam->niNameInfo.Buffer);
						}
					}
				}
			}
		}
		else
		{
			//thread stuck
			//TerminateThread(hThNtQueryObjectHandle, 0);
			wprintf(L".");
		}
		CloseHandle(hDuplicatedHandle);
		LocalFree(thsParam);
	}

	PWSTR pwszSorted = NULL;
	SortUniqueMultilineWchar(pwszTempBuf, &pwszSorted);
	StringCchCatW(pwszHndBuf, stHndBufSize / sizeof(WCHAR), pwszSorted);
	LocalFree(pwszSorted);

	LocalFree(pwszTempBuf);
	LocalFree(pAllHandleInfo);
	if (hProcHandle)
	{
		CloseHandle(hProcHandle);
	}
	wprintf(L"\rListing Handles%*s\r", BLANKS_TO_WRITE, L" ");
	return TRUE;
}


PWSTR HND_Output(void)
{
	wprintf(L"Listing Handles");
	stHndBufSize = SIZE_16MB;

	pwszHndBuf = LocalAlloc(LPTR, stHndBufSize);
	CRASHIFNULLALLOC(pwszHndBuf);

	AddCheckHeader(pwszHndBuf, stHndBufSize, L"Open Handles", TRUE);

	HNDMain();

	ShrinkWcharBuffer(&pwszHndBuf);
	wprintf(L"\r\n");

	return pwszHndBuf;
}
