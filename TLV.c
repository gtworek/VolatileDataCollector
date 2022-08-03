#include "VSTriage.h"

PWSTR pwszTlvBuf = NULL;
size_t stTlvBufSize;

HANDLE TLVGetProcessBestHandle(DWORD dwPid)
{
	HANDLE hProcess;
	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
	if (!hProcess)
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		if (!hProcess)
		{
			hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
		}
	}
	return hProcess;
}

DWORD TLVGetProcessExe(HANDLE hProcess, PWSTR pwszExe, size_t dwSize)
{
	DWORD dwP1;
	dwP1 = (DWORD)dwSize;
	if (QueryFullProcessImageNameW(hProcess, 0, pwszExe, &dwP1))
	{
		return 0;
	}
	if (QueryFullProcessImageNameW(hProcess, PROCESS_NAME_NATIVE, pwszExe, &dwP1))
	{
		return 0;
	}
	StringCchPrintfW(pwszExe, dwSize, L"(ERROR %i)", GetLastError());
	return GetLastError();
}

DWORD TLVGetProcessCmdLine(HANDLE hProcess, PWSTR pwszCmdLine, size_t dwSize)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION procInfo = {0};
	ULONG cbNeeded2 = 0;
	PEB peb;
	RTL_USER_PROCESS_PARAMETERS upp;

	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &procInfo, sizeof(procInfo), &cbNeeded2);
	if (0 == status)
	{
		if (0 != procInfo.PebBaseAddress)
		{
			if (ReadProcessMemory(hProcess, procInfo.PebBaseAddress, &peb, sizeof(peb), NULL))
			{
				if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), NULL))
				{
					WCHAR* commandLineContents = (WCHAR*)LocalAlloc(LPTR, ((size_t)upp.CommandLine.Length + 2));

					if (ReadProcessMemory(
						hProcess,
						upp.CommandLine.Buffer,
						commandLineContents,
						upp.CommandLine.Length,
						0))
					{
						StringCchPrintfW(pwszCmdLine, dwSize, L"%s", commandLineContents);
						LocalFree(commandLineContents);
						return 0;
					}
					StringCchPrintfW(pwszCmdLine, dwSize, L"(ERROR %i)", GetLastError());
					LocalFree(commandLineContents);
					return GetLastError();
				}
				StringCchPrintfW(pwszCmdLine, dwSize, L"(ERROR %i)", GetLastError());
				return GetLastError();
			}
			StringCchPrintfW(pwszCmdLine, dwSize, L"(ERROR %i)", GetLastError());
			return GetLastError();
		}
	}
	StringCchPrintfW(pwszCmdLine, dwSize, L"????");
	return status;
}

DWORD TLVGetProcessUser(HANDLE hProcess, PWSTR pwszUserName, size_t stSize)
{
	BOOL bRes;
	DWORD dwRes;
	HANDLE hToken;
	DWORD dwTokenLength;
	PTOKEN_USER ptuTokenInformation;
	DWORD dwUserNameLen = USERNAME_LENGTH;
	DWORD dwDomainNameLen = DOMAINNAME_LENGTH;
	TCHAR szUserName[USERNAME_LENGTH];
	TCHAR szDomainName[DOMAINNAME_LENGTH];
	SID_NAME_USE snuSidUse;

	bRes = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!bRes)
	{
		StringCchPrintfW(pwszUserName, stSize, L"????");
		return GetLastError();
	}

	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenLength);
	ptuTokenInformation = (PTOKEN_USER)LocalAlloc(LPTR, dwTokenLength);
	if (NULL == ptuTokenInformation)
	{
		CloseHandle(hToken);
		StringCchPrintfW(pwszUserName, stSize, L"????");
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	bRes = GetTokenInformation(hToken, TokenUser, ptuTokenInformation, dwTokenLength, &dwTokenLength);
	if (!bRes)
	{
		dwRes = GetLastError();
		CloseHandle(hToken);
		LocalFree(ptuTokenInformation);
		StringCchPrintfW(pwszUserName, stSize, L"????");
		return dwRes;
	}

	if (!LookupAccountSid(
		NULL,
		ptuTokenInformation->User.Sid,
		szUserName,
		&dwUserNameLen,
		szDomainName,
		&dwDomainNameLen,
		&snuSidUse))
	{
		dwRes = GetLastError();
		CloseHandle(hToken);
		LocalFree(ptuTokenInformation);
		StringCchPrintfW(pwszUserName, stSize, L"????");
		return dwRes;
	}

	CloseHandle(hToken);
	LocalFree(ptuTokenInformation);

	StringCchPrintfW(pwszUserName, stSize, L"%s\\%s", szDomainName, szUserName);
	return 0;
}


DWORD TLVGetProcessSessionId(HANDLE hProcess, PWSTR pwszSessionId, size_t stSize)
{
	BOOL bRes;
	HANDLE hToken;
	DWORD dwTokenLength;
	DWORD dwSessionId;

	bRes = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!bRes)
	{
		StringCchPrintfW(pwszSessionId, stSize, L"?");
		return GetLastError();
	}

	bRes = GetTokenInformation(hToken, TokenSessionId, &dwSessionId, sizeof(DWORD), &dwTokenLength);
	if (!bRes)
	{
		DWORD dwRes;
		dwRes = GetLastError();
		CloseHandle(hToken);
		StringCchPrintfW(pwszSessionId, stSize, L"?");
		return dwRes;
	}

	CloseHandle(hToken);

	StringCchPrintfW(pwszSessionId, stSize, L"%i", dwSessionId);
	return 0;
}


DWORD TLVGetProcessTimesStr(HANDLE hProcess, PWSTR pwszTimes, size_t stSize)
{
	BOOL bRes;
	FILETIME ftCreationTime;
	FILETIME ftExitTime;
	FILETIME ftKernelTime;
	FILETIME ftUserTime;
	SYSTEMTIME stCreationTime;
	SYSTEMTIME stKernelTime;
	SYSTEMTIME stUserTime;

	bRes = GetProcessTimes(
		hProcess,
		&ftCreationTime,
		&ftExitTime,
		&ftKernelTime,
		&ftUserTime
	);
	if (!bRes)
	{
		StringCchPrintfW(pwszTimes, stSize, L"??:??");
		return GetLastError();
	}

	FileTimeToSystemTime(&ftCreationTime, &stCreationTime);
	FileTimeToSystemTime(&ftKernelTime, &stKernelTime);
	FileTimeToSystemTime(&ftUserTime, &stUserTime);

	INT64 i1;
	i1 = (INT64)MAXDWORD * ftKernelTime.dwHighDateTime + ftKernelTime.dwLowDateTime;
	i1 = i1 / TICKS_IN_MS;

	INT64 i2;
	i2 = (INT64)MAXDWORD * ftUserTime.dwHighDateTime + ftUserTime.dwLowDateTime;
	i2 = i2 / TICKS_IN_MS;

	StringCchPrintfW(
		pwszTimes,
		stSize,
		L"\r\n\t\tStart: %04i-%02i-%02iT%02i:%02i:%02iZ\r\n\t\tKernel: %llums\r\n\t\tUser: %llums",
		stCreationTime.wYear,
		stCreationTime.wMonth,
		stCreationTime.wDay,
		stCreationTime.wHour,
		stCreationTime.wMinute,
		stCreationTime.wSecond,
		i1,
		i2);
	return 0;
}


DWORD TLVGetProcessIOPerf(HANDLE hProcess, PWSTR pwszSessionId, DWORD dwSize)
{
	BOOL bRes;
	HANDLE hToken;
	DWORD dwTokenLength;
	DWORD dwSessionId;

	bRes = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!bRes)
	{
		StringCchPrintfW(pwszSessionId, dwSize, L"?");
		return GetLastError();
	}

	bRes = GetTokenInformation(hToken, TokenSessionId, &dwSessionId, sizeof(DWORD), &dwTokenLength);
	if (!bRes)
	{
		DWORD dwRes;
		dwRes = GetLastError();
		CloseHandle(hToken);
		StringCchPrintfW(pwszSessionId, dwSize, L"?");
		return dwRes;
	}

	CloseHandle(hToken);

	StringCchPrintfW(pwszSessionId, dwSize, L"%i", dwSessionId);
	return 0;
}

PWSTR TLVGetProcessDetails(HANDLE hProcess)
{
	if (!hProcess)
	{
		return NULL;
	}

	PWCHAR pwszPathData;
	PWCHAR pwszProcDataTemp;
	PWCHAR pwszProcData;
	size_t stPathDataSize;
	size_t stProcDataTempSize;
	size_t stProcDataSize;

	DWORD dwResult;

	stPathDataSize = SIZE_1MB;
	stProcDataSize = SIZE_1MB;
	stProcDataTempSize = SIZE_1MB;

	pwszPathData = LocalAlloc(LPTR, stPathDataSize);
	CRASHIFNULLALLOC(pwszPathData);
	pwszProcData = LocalAlloc(LPTR, stProcDataSize);
	CRASHIFNULLALLOC(pwszProcData);
	pwszProcDataTemp = LocalAlloc(LPTR, stProcDataTempSize);
	CRASHIFNULLALLOC(pwszProcDataTemp);


	//full path
	dwResult = TLVGetProcessExe(hProcess, pwszPathData, stPathDataSize / sizeof(WCHAR));
	if (!dwResult)
	{
		StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tPath: %s\r\n", pwszPathData);
		StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
	}


	//cmdline
	dwResult = TLVGetProcessCmdLine(hProcess, pwszPathData, stPathDataSize / sizeof(WCHAR));
	if (!dwResult)
	{
		StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tCmdline: %s\r\n", pwszPathData);
		StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
	}


	//user
	dwResult = TLVGetProcessUser(hProcess, pwszPathData, stPathDataSize / sizeof(WCHAR));
	if (!dwResult)
	{
		StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tUser: %s\r\n", pwszPathData);
		StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
	}


	//session
	dwResult = TLVGetProcessSessionId(hProcess, pwszPathData, stPathDataSize / sizeof(WCHAR));
	if (!dwResult)
	{
		StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tSession: %s\r\n", pwszPathData);
		StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
	}


	//times
	dwResult = TLVGetProcessTimesStr(hProcess, pwszPathData, stPathDataSize / sizeof(WCHAR));
	if (!dwResult)
	{
		StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tTimes: %s\n", pwszPathData);
		StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
	}

	LocalFree(pwszProcDataTemp);
	LocalFree(pwszPathData);
	return pwszProcData;
}


PSYSTEM_PROCESS_INFORMATION TLVFindProcessInformation(ULONG ulPid, PSYSTEM_PROCESS_INFORMATION psPiHead)
{
	PSYSTEM_PROCESS_INFORMATION psIt1;
	psIt1 = psPiHead;
	while (psIt1 != NULL)
	{
		if (0 == psIt1->NextEntryOffset)
		{
			return NULL;
		}
		if (ulPid == HandleToULong(psIt1->UniqueProcessId))
		{
			break;
		}
		psIt1 = Add2Ptr(psIt1, psIt1->NextEntryOffset);
	}
	return psIt1;
}


BOOL TLVMain(void)
{
	HANDLE hSnapshot;
	ULONG ulBufferSize;
	PSYSTEM_PROCESS_INFORMATION psPIArray;
	NTSTATUS status;

	psPIArray = NULL;
	ulBufferSize = 0;
	status = STATUS_INFO_LENGTH_MISMATCH;

	while (STATUS_INFO_LENGTH_MISMATCH == status)
	{
		if (psPIArray)
		{
			LocalFree(psPIArray);
		}
		psPIArray = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc(LPTR, ulBufferSize);
		CRASHIFNULLALLOC(psPIArray);
		status = NtQuerySystemInformation(SystemProcessInformation, psPIArray, ulBufferSize, &ulBufferSize);
	}
	if (STATUS_SUCCESS != status)
	{
		LocalFree(psPIArray);
		return FALSE;
	}

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		LocalFree(psPIArray);
		return FALSE;
	}

	// size_t stTemp;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);


	if (Process32FirstW(hSnapshot, &pe32))
	{
		PSYSTEM_PROCESS_INFORMATION psPI;
		//		HRESULT hResult;
		HANDLE hProcess;
		do
		{
			PWSTR pwszProcData;
			size_t stProcDataSize;
			PWSTR pwszProcDataTemp;
			size_t stProcDataTempSize;

			stProcDataSize = SIZE_1MB;
			stProcDataTempSize = SIZE_1KB;

			pwszProcData = LocalAlloc(LPTR, stProcDataSize);
			CRASHIFNULLALLOC(pwszProcData);

			pwszProcDataTemp = LocalAlloc(LPTR, stProcDataTempSize);
			CRASHIFNULLALLOC(pwszProcDataTemp);

			StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"PID: %i\r\n", pe32.th32ProcessID);
			StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);

			StringCchPrintfW(pwszProcDataTemp, stProcDataTempSize / sizeof(WCHAR), L"\tName: %s\r\n", pe32.szExeFile);
			StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);

			StringCchPrintfW(
				pwszProcDataTemp,
				stProcDataTempSize / sizeof(WCHAR),
				L"\tPPID: %i\r\n",
				pe32.th32ParentProcessID);
			StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);

			StringCchPrintfW(
				pwszProcDataTemp,
				stProcDataTempSize / sizeof(WCHAR),
				L"\tThreads: %i\r\n",
				pe32.cntThreads);
			StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);


			hProcess = TLVGetProcessBestHandle(pe32.th32ProcessID);

			if (NULL != hProcess)
			{
				PWSTR pwszDetails;
				pwszDetails = TLVGetProcessDetails(hProcess);
				StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszDetails);
				CloseHandle(hProcess);
				LocalFree(pwszDetails);
			}


			psPI = TLVFindProcessInformation(pe32.th32ProcessID, psPIArray);
			if (NULL != psPI)
			{
				StringCchPrintfW(
					pwszProcDataTemp,
					stProcDataTempSize / sizeof(WCHAR),
					L"\tIOCount: \r\n\t\tRead: %llu\r\n\t\tWrite: %llu\r\n\t\tOther: %llu\r\n",
					psPI->ReadOperationCount.QuadPart,
					psPI->WriteOperationCount.QuadPart,
					psPI->OtherOperationCount.QuadPart);
				StringCchCatW(pwszProcData, stProcDataSize / sizeof(WCHAR), pwszProcDataTemp);
			}

			StringCchCatW(pwszTlvBuf, stTlvBufSize / sizeof(WCHAR), pwszProcData);

			//TLVBufResize();
			ResizeWcharBufIfNeeded(&pwszTlvBuf, &stTlvBufSize);

			LocalFree(pwszProcDataTemp);
			LocalFree(pwszProcData);
		}
		while (Process32NextW(hSnapshot, &pe32));
	}
	else
	{
		wprintf(L"Process32First failed. Error: %lu\r\n", GetLastError());
		LocalFree(psPIArray);
		return FALSE;
	}
	CloseHandle(hSnapshot);
	LocalFree(psPIArray);
	return TRUE;
}

PWSTR TLV_Output(void)
{
	wprintf(L"Listing Processes\r\n");
	stTlvBufSize = SIZE_1MB;

	pwszTlvBuf = LocalAlloc(LPTR, stTlvBufSize);
	if (!pwszTlvBuf)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	AddCheckHeader(pwszTlvBuf, stTlvBufSize, L"Process Details", TRUE);

	if (!TLVMain())
	{
		wprintf(L"\tSome errors...\r\n");
	}

	ShrinkWcharBuffer(&pwszTlvBuf);
	return pwszTlvBuf;
}
