#include "VSTriage.h"

PWSTR pwszTlm2Buf = NULL;
size_t stTlm2BufSize;

BOOL IsProcesWoWTLM2(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;
	IsWow64Process(hProcess, &bIsWow64);
	return bIsWow64;
}

PWSTR TLM2GetLoadReasonString(LDR_DLL_LOAD_REASON lrReason)
{
	PWSTR pwszLRString;
	DWORD dwLRBufChCount = SIZE_1KB; //will be enough
	ALLOCORCRASH(pwszLRString, dwLRBufChCount * sizeof(WCHAR));

	switch (lrReason)
	{
	case LoadReasonStaticDependency:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonStaticDependency");
		break;
	case LoadReasonStaticForwarderDependency:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonStaticForwarderDependency");
		break;
	case LoadReasonDynamicForwarderDependency:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonDynamicForwarderDependency");
		break;
	case LoadReasonDelayloadDependency:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonDelayloadDependency");
		break;
	case LoadReasonDynamicLoad:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonDynamicLoad");
		break;
	case LoadReasonAsImageLoad:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonAsImageLoad");
		break;
	case LoadReasonAsDataLoad:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonAsDataLoad");
		break;
	case LoadReasonEnclavePrimary:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonEnclavePrimary");
		break;
	case LoadReasonEnclaveDependency:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonEnclaveDependency");
		break;
	case LoadReasonUnknown:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"LoadReasonUnknown");
		break;
	default:
		StringCchPrintfW(pwszLRString, dwLRBufChCount, L"%s", L"?");
	}
	return pwszLRString;
}

PWSTR TLM2GetFlagsString(LDR_DATA_TABLE_ENTRY ldrEntryData)
{
	PWSTR pwszFlagsString;
	ALLOCORCRASH(pwszFlagsString, SIZE_1MB);

	PWSTR pwszFlagsTemp;
	ALLOCORCRASH(pwszFlagsTemp, SIZE_1KB);

	if (0UL != ldrEntryData.PackagedBinary)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tPackagedBinary\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.MarkedForRemoval)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tMarkedForRemoval\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ImageDll)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tImageDll\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.LoadNotificationsSent)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tLoadNotificationsSent\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.TelemetryEntryProcessed)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tTelemetryEntryProcessed\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ProcessStaticImport)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tProcessStaticImport\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.InLegacyLists)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tInLegacyLists\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.InIndexes)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tInIndexes\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ShimDll)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tShimDll\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.InExceptionTable)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tInExceptionTable\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ReservedFlags1)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tReservedFlags1\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.LoadInProgress)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tLoadInProgress\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.LoadConfigProcessed)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tLoadConfigProcessed\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.EntryProcessed)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tEntryProcessed\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ProtectDelayLoad)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tProtectDelayLoad\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ReservedFlags3)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tReservedFlags3\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.DontCallForThreads)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tDontCallForThreads\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ProcessAttachCalled)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tProcessAttachCalled\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ProcessAttachFailed)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tProcessAttachFailed\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.CorDeferredValidate)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tCorDeferredValidate\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.CorImage)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tCorImage\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.DontRelocate)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tDontRelocate\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.CorILOnly)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tCorILOnly\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ChpeImage)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tChpeImage\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ReservedFlags5)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tReservedFlags5\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.Redirected)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tRedirected\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.ReservedFlags6)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tReservedFlags6\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	if (0UL != ldrEntryData.CompatDatabaseProcessed)
	{
		StringCchPrintfW(pwszFlagsTemp, LocalSize(pwszFlagsTemp) / sizeof(WCHAR), L"\t\t\tCompatDatabaseProcesses\r\n");
		StringCchCatW(pwszFlagsString, LocalSize(pwszFlagsString) / sizeof(WCHAR), pwszFlagsTemp);
	}

	LocalFree(pwszFlagsTemp);
	return pwszFlagsString;
}

PWSTR TLM2GetProcessModules(HANDLE hProcessHandle)
{
	PROCESS_BASIC_INFORMATION basicInfo;
	NTSTATUS status;
	PPEB pPeb;
	PPEB_LDR_DATA ldr = NULL;
	PLIST_ENTRY ldrHead;
	PLIST_ENTRY ldrNext;
	PLDR_DATA_TABLE_ENTRY ldrEntry;
	LDR_DATA_TABLE_ENTRY ldrEntryData;
	PWSTR pwszData;
	PWSTR pwszTmpName;
	DWORD dwCtr = 0;
	LONGLONG llZeroTime = 0;

	size_t dwDataTempBytes = SIZE_1MB;
	size_t dwDataBytes = SIZE_16MB;

	PWSTR pwszDataTemp;
	ALLOCORCRASH(pwszDataTemp, dwDataTempBytes);
	ALLOCORCRASH(pwszData, dwDataBytes);

	StringCchPrintfW(pwszDataTemp, dwDataTempBytes / sizeof(WCHAR), L"%i:\r\n", GetProcessId(hProcessHandle));
	StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

	// Get the process info.
	status = NtQueryInformationProcess(
		hProcessHandle,
		ProcessBasicInformation,
		&basicInfo,
		sizeof(basicInfo),
		NULL
	);

	if (0 != status)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"\t(ERROR: NtQueryInformationProcess %i)\r\n",
			status);
		StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
		LocalFree(pwszDataTemp);
		return pwszData;
	}

	pPeb = basicInfo.PebBaseAddress;

	if (NULL == pPeb)
	{
		StringCchPrintfW(pwszDataTemp, dwDataTempBytes / sizeof(WCHAR), L"\t(ERROR: Cannot find PEB)\r\n");
		StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
		LocalFree(pwszDataTemp);
		return pwszData;
	}

	//
	// ldr = peb->Ldr
	//

	if (!ReadProcessMemory(hProcessHandle, (LPCVOID)&pPeb->Ldr, &ldr, sizeof(ldr), NULL))
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"\t(ERROR: ReadProcessMemory %i)\r\n",
			GetLastError());
		StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
		LocalFree(pwszDataTemp);
		return pwszData;
	}

	ldrHead = &ldr->InMemoryOrderModuleList;

	//
	// ldrNext = ldrHead->Flink;
	//

	if (!ReadProcessMemory(hProcessHandle, (LPCVOID)&ldrHead->Flink, &ldrNext, sizeof(ldrNext), NULL))
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"\t(ERROR: ReadProcessMemory %i)\r\n",
			GetLastError());
		StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
		LocalFree(pwszDataTemp);
		return pwszData;
	}

	//loop over modules
	while (ldrNext != ldrHead)
	{
		ldrEntry = CONTAINING_RECORD(
			ldrNext,
			LDR_DATA_TABLE_ENTRY,
			InMemoryOrderLinks
		);

		if (!ReadProcessMemory(hProcessHandle, (LPCVOID)ldrEntry, &ldrEntryData, sizeof(ldrEntryData), NULL))
		{
			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t(ERROR: ReadProcessMemory %i)\r\n",
				GetLastError());
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
		}
		else
		{
			//allocating too much but it doesnt hurt while makes error message fit for sure
			ALLOCORCRASH(pwszTmpName, ldrEntryData.FullDllName.MaximumLength + (SIZE_T)64);
			if (!ReadProcessMemory(
				hProcessHandle,
				(LPCVOID)ldrEntryData.FullDllName.Buffer,
				pwszTmpName,
				ldrEntryData.FullDllName.MaximumLength,
				NULL))
			{
				StringCchPrintfW(
					pwszTmpName,
					LocalSize(pwszTmpName) / sizeof(WCHAR),
					L"(ERROR: ReadProcessMemory %i)",
					GetLastError());
			}

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\tFullDllName: %s\r\n",
				pwszTmpName);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
			LocalFree(pwszTmpName);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tDLLBase: 0x%llx\r\n",
				(ULONG_PTR)ldrEntryData.DllBase);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tSizeOfImage: 0x%lx\r\n",
				ldrEntryData.SizeOfImage);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tParentDllBase: 0x%llx\r\n",
				(ULONG_PTR)ldrEntryData.ParentDllBase);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tOriginalBase: 0x%llx\r\n",
				ldrEntryData.OriginalBase);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tImplicitPathOptions: 0x%lx\r\n",
				ldrEntryData.ImplicitPathOptions);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tDependentLoadFlags: 0x%lx\r\n",
				ldrEntryData.DependentLoadFlags);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			SYSTEMTIME stStamp;
			PWSTR pwszTimestamp;

			FileTimeToSystemTime((FILETIME*)&(ldrEntryData.LoadTime.QuadPart), &stStamp);
			pwszTimestamp = SystemTimeToISO8601(stStamp);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tLoadTime: %s",
				pwszTimestamp);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
			LocalFree(pwszTimestamp);

			if (0 == dwCtr)
			{
				llZeroTime = ldrEntryData.LoadTime.QuadPart;
			}
			else
			{
				StringCchPrintfW(
					pwszDataTemp,
					dwDataTempBytes / sizeof(WCHAR),
					L" (+%lldms)",
					(ldrEntryData.LoadTime.QuadPart - llZeroTime) / TICKS_PER_MS);
				StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
			}
			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\r\n");
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			PWSTR pwszT1;
			pwszT1 = TLM2GetLoadReasonString((ldrEntryData.LoadReason));
			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tLoad Reason: %d (%s)\r\n",
				(int)(ldrEntryData.LoadReason),
				pwszT1);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
			LocalFree(pwszT1);

			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"\t\tFlags: 0x%x\r\n",
				(int)(ldrEntryData.Flags));
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);

			pwszT1 = TLM2GetFlagsString(ldrEntryData);
			StringCchPrintfW(
				pwszDataTemp,
				dwDataTempBytes / sizeof(WCHAR),
				L"%s",
				pwszT1);
			StringCchCatW(pwszData, dwDataBytes / sizeof(WCHAR), pwszDataTemp);
			LocalFree(pwszT1);
		}

		//finish loop
		ldrNext = ldrEntryData.InMemoryOrderLinks.Flink;
		dwCtr++;
		ResizeWcharBufIfNeeded(&pwszData, &dwDataBytes);
	} //loop over modules
	LocalFree(pwszDataTemp);
	return pwszData;
}


BOOL TLM2Main(void)
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
			pwszModules = TLM2GetProcessModules(hProcess);
			StringCchCatW(pwszTlm2Buf, stTlm2BufSize, pwszModules);
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
				L"%i:\r\n\t(ERROR %i)\r\n",
				pdwProcArr[i],
				dwLastError);
			StringCchCatW(pwszTlm2Buf, stTlm2BufSize, pwszError);
			LocalFree(pwszError);
		}
		ResizeWcharBufIfNeeded(&pwszTlm2Buf, &stTlm2BufSize);
	}
	LocalFree(pdwProcArr);
	return TRUE;
}


PWSTR TLM2_Output(void)
{
	wprintf(L"Listing 64bit Modules from PEB\r\n");
	stTlm2BufSize = SIZE_16MB;

	ALLOCORCRASH(pwszTlm2Buf, stTlm2BufSize);
	AddCheckHeader(pwszTlm2Buf, stTlm2BufSize, L"Modules from PEB", TRUE);

	TLM2Main();

	ShrinkWcharBuffer(&pwszTlm2Buf);
	return pwszTlm2Buf;
}
