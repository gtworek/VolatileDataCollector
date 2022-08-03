#include "VSTriage.h"

PWSTR pwszTlmBuf = NULL;
size_t stTlmBufSize;

//todo: IsWow64Process2 for non-win7build

BOOL IsProcesWoW(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;
	IsWow64Process(hProcess, &bIsWow64);
	return bIsWow64;
}

PWSTR TLMGetProcessModules(HANDLE hProcess)
{
	DWORD cbAllocated;
	DWORD cbNeeded = 0;
	size_t dwProcDataBytes = SIZE_1MB;
	size_t dwProcDataTempBytes = SIZE_1MB;
	BOOL bRes;
	HMODULE* hModArr = NULL;
	PWSTR pwszProcData;
	PWSTR pwszProcDataTemp;
	ALLOCORCRASH(pwszProcData, dwProcDataBytes);
	ALLOCORCRASH(pwszProcDataTemp, dwProcDataTempBytes);

	do
	{
		cbAllocated = cbNeeded;
		cbNeeded = 0;
		LocalFree(hModArr);
		ALLOCORCRASH(hModArr, cbAllocated);
		bRes = EnumProcessModulesEx(
			hProcess,
			hModArr,
			cbAllocated,
			&cbNeeded,
			LIST_MODULES_ALL
		);
		if (!bRes)
		{
			break;
		}
	}
	while (cbNeeded != cbAllocated);

	//copy the buffer
	HMODULE* hModArrCopy;
	ALLOCORCRASH(hModArrCopy, LocalSize(hModArr));
	memcpy_s(hModArrCopy, LocalSize(hModArr), hModArr, LocalSize(hModArr));
	LocalFree(hModArr);

	if (bRes)
	{
		WCHAR wszProcessName[SIZE_1KB];

		GetModuleBaseNameW(
			hProcess,
			hModArrCopy[0],
			wszProcessName,
			ARRAYSIZE(wszProcessName));

		StringCchPrintfW(
			pwszProcDataTemp,
			dwProcDataTempBytes / sizeof(WCHAR),
			L"%i:\t%s",
			GetProcessId(hProcess),
			wszProcessName);
		StringCchCatW(pwszProcData, dwProcDataBytes / sizeof(WCHAR), pwszProcDataTemp);

		if (IsProcesWoW(hProcess))
		{
			StringCchCatW(pwszProcData, dwProcDataBytes / sizeof(WCHAR), L"\t(WOW)");
		}
		StringCchCatW(pwszProcData, dwProcDataBytes / sizeof(WCHAR), L"\r\n");

		for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++)
		{
			WCHAR wszModName[SIZE_1KB] = {0};
			WCHAR wszMapName[SIZE_1KB] = {0};
			GetModuleFileNameExW(hProcess, hModArrCopy[i], wszModName, ARRAYSIZE(wszModName));
			GetMappedFileNameW(hProcess, hModArrCopy[i], wszMapName, ARRAYSIZE(wszMapName));

			// Print the module name and handle value.
			StringCchPrintfW(
				pwszProcDataTemp,
				dwProcDataTempBytes / sizeof(WCHAR),
				L"\t%s\t%s\t(0x%p)\r\n",
				wszModName,
				wszMapName,
				hModArrCopy[i]);
			StringCchCatW(
				pwszProcData,
				dwProcDataBytes / sizeof(WCHAR),
				pwszProcDataTemp);
			ResizeWcharBufIfNeeded(&pwszProcData, &dwProcDataBytes);
		}
	}
	else
	{
		StringCchPrintfW(
			pwszProcDataTemp,
			dwProcDataTempBytes / sizeof(WCHAR),
			L"%i:\t(cannot get details)",
			GetProcessId(hProcess));
		StringCchCatW(pwszProcData, dwProcDataBytes / sizeof(WCHAR), pwszProcDataTemp);
	}
	LocalFree(hModArrCopy);
	LocalFree(pwszProcDataTemp);
	return pwszProcData;
}


BOOL TLMMain(void)
{
	DWORD cbNeeded;
	DWORD cProcesses;
	DWORD i;
	DWORD dwProcArrSize;
	PDWORD pdwProcArr;
	HANDLE hProcess;
	DWORD dwLastError;

	// Get the list of process identifiers.

	dwProcArrSize = INITIAL_PROCESS_COUNT * sizeof(DWORD);
	pdwProcArr = LocalAlloc(LPTR, dwProcArrSize);
	CRASHIFNULLALLOC(pdwProcArr);

	EnumProcesses(pdwProcArr, dwProcArrSize, &cbNeeded);
	while (dwProcArrSize == cbNeeded)
	{
		LocalFree(pdwProcArr);
		dwProcArrSize *= 2;
		pdwProcArr = LocalAlloc(LPTR, dwProcArrSize);
		CRASHIFNULLALLOC(pdwProcArr);
		EnumProcesses(pdwProcArr, dwProcArrSize, &cbNeeded);
	}
	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			pdwProcArr[i]);
		dwLastError = GetLastError();
		if (NULL != hProcess)
		{
			PWSTR pwszModules;
			pwszModules = TLMGetProcessModules(hProcess);
			StringCchCatW(pwszTlmBuf, stTlmBufSize, pwszModules);
			LocalFree(pwszModules);
			CloseHandle(hProcess);
		}
		else
		{
			PWSTR pwszError;
			ALLOCORCRASH(pwszError, SIZE_1KB);
			StringCchPrintfW(
				pwszError,
				LocalSize(pwszError) / sizeof(WCHAR),
				L"%i:\t(ERROR %i)\r\n",
				pdwProcArr[i],
				dwLastError);
			StringCchCatW(pwszTlmBuf, stTlmBufSize, pwszError);
			LocalFree(pwszError);
		}
		ResizeWcharBufIfNeeded(&pwszTlmBuf, &stTlmBufSize);
	}
	LocalFree(pdwProcArr);
	return TRUE;
}


PWSTR TLM_Output(void)
{
	wprintf(L"Listing DLLs\r\n");
	stTlmBufSize = SIZE_16MB;

	ALLOCORCRASH(pwszTlmBuf, stTlmBufSize);
	AddCheckHeader(pwszTlmBuf, stTlmBufSize, L"Loaded Modules", TRUE);

	TLMMain();

	ShrinkWcharBuffer(&pwszTlmBuf);
	return pwszTlmBuf;
}
