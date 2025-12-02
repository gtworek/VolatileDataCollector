#include "VSTriage.h"

PWSTR pwszSetBuf;
size_t stSetBufSize;

typedef struct
{
	PWSTR pwszVarName;
	PWSTR pwszVarValue;
} VarEntry, *PVARENTRY;

PVARENTRY pvOwnEnvArray;
DWORD dwOwnEnvEntryCount;

DWORD SETEnvBlockToArray(PVOID pwszEnvBlock, PVARENTRY* pVarEntry)
{
	if (NULL == pwszEnvBlock)
	{
		*pVarEntry = NULL;
		return 0;
	}

	DWORD dwEntryCount = 0;
	PWSTR pwszCurrentVar;
	pwszCurrentVar = (PWSTR)pwszEnvBlock;
	while (*pwszCurrentVar)
	{
		dwEntryCount++;
		pwszCurrentVar += wcslen(pwszCurrentVar) + 1; //include NULL
	}
	PVARENTRY pVarEntryLocal;
	ALLOCORCRASH(pVarEntryLocal, dwEntryCount * sizeof(VarEntry));


	pwszCurrentVar = (PWSTR)pwszEnvBlock;
	for (DWORD i = 0; i < dwEntryCount; i++)
	{
		//iterate again to fill the array, splitting name and value on '='
		//we can have some weird env vars like "=C:" yielding empty names so be careful when parsing the resulting array
		PWSTR pwszName;
		PWSTR pwszValue;
		DWORD dwEqPos;
		dwEqPos = (DWORD)wcscspn(pwszCurrentVar, L"=");
		ALLOCORCRASH(pwszName, (dwEqPos + 1) * sizeof(WCHAR));
		memcpy(pwszName, pwszCurrentVar, dwEqPos * sizeof(WCHAR));
		pVarEntryLocal[i].pwszVarName = pwszName;
		ALLOCORCRASH(pwszValue, (wcslen(pwszCurrentVar) - dwEqPos + 1) * sizeof(WCHAR));
		memcpy(pwszValue, pwszCurrentVar + dwEqPos + 1, (wcslen(pwszCurrentVar) - dwEqPos) * sizeof(WCHAR));
		pVarEntryLocal[i].pwszVarValue = pwszValue;
		pwszCurrentVar += wcslen(pwszCurrentVar) + 1; //include NULL
	}

	*pVarEntry = pVarEntryLocal;
	return dwEntryCount;
}

PWSTR SETEnvBlockToString(PVOID pEnvBlock)
{
	PWSTR pwszEnvString;
	SIZE_T stEnvString;
	stEnvString = (NT_MAX_PATH * sizeof(WCHAR)) + SIZE_1KB; //max env var size + some extra
	ALLOCORCRASH(pwszEnvString, stEnvString);

	PWSTR pwszCurrentEnvVar;
	pwszCurrentEnvVar = (PWSTR)pEnvBlock;

	while (*pwszCurrentEnvVar)
	{
		HRESULT hResult;
		hResult = StringCchCatW(pwszEnvString, NT_MAX_PATH, L"\t");
		CHECKSTRINGHR(hResult);
		hResult = StringCchCatW(pwszEnvString, NT_MAX_PATH, pwszCurrentEnvVar);
		CHECKSTRINGHR(hResult);
		hResult = StringCchCatW(pwszEnvString, NT_MAX_PATH, L"\r\n");
		CHECKSTRINGHR(hResult);
		ResizeWcharBufIfNeeded(&pwszEnvString, &stEnvString);
		pwszCurrentEnvVar += wcslen(pwszCurrentEnvVar) + 1; // include NULL
	}

	ShrinkWcharBuffer(&pwszEnvString);
	return pwszEnvString;
}

VOID SETCleanEnvArray(PVARENTRY pVarEntry, DWORD dwEntryCount)
{
	if (NULL == pVarEntry)
	{
		return;
	}
	for (DWORD i = 0; i < dwEntryCount; i++)
	{
		LocalFree(pVarEntry[i].pwszVarName);
		LocalFree(pVarEntry[i].pwszVarValue);
	}
	LocalFree(pVarEntry);
}


PWSTR SETEnvBlockToDiffString(PVOID pEnvBlock)
{
	PWSTR pwszDiffStr;
	size_t stDiffBufSize;
	DWORD dwProcessEnvEntryCount;
	PVARENTRY pvProcessEnvArray;
	BOOL bNoDiff = TRUE;

	dwProcessEnvEntryCount = SETEnvBlockToArray(pEnvBlock, &pvProcessEnvArray);
	stDiffBufSize = NT_MAX_PATH * sizeof(WCHAR);
	ALLOCORCRASH(pwszDiffStr, stDiffBufSize);

	//nameless env vars first
	for (DWORD i = 0; i < dwProcessEnvEntryCount; i++)
	{
		BOOL bFound = FALSE;
		if (0 != wcslen(pvProcessEnvArray[i].pwszVarName))
		{
			continue; //var has a name, skip now
		}
		for (DWORD j = 0; j < dwOwnEnvEntryCount; j++)
		{
			if (0 != wcslen(pvOwnEnvArray[i].pwszVarName))
			{
				continue; //var has a name, skip now
			}
			if (0 == wcscmp(pvProcessEnvArray[i].pwszVarValue, pvOwnEnvArray[j].pwszVarValue))
			{
				bFound = TRUE;
				break; //same nameless var found, no need to add to diff
			}
		}

		if (!bFound)
		{
			//not found in own nameless vars
			HRESULT hResult;
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t+ ");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"=");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvProcessEnvArray[i].pwszVarValue);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\r\n");
			CHECKSTRINGHR(hResult);
			ResizeWcharBufIfNeeded(&pwszDiffStr, &stDiffBufSize);
		}
	}

	//check for vars that exist in process, but not in own
	for (DWORD j = 0; j < dwOwnEnvEntryCount; j++)
	{
		BOOL bFound = FALSE;
		if (0 != wcslen(pvOwnEnvArray[j].pwszVarName))
		{
			continue; //var has a name, skip now
		}
		for (DWORD i = 0; i < dwProcessEnvEntryCount; i++)
		{
			if (0 != wcslen(pvProcessEnvArray[i].pwszVarName))
			{
				continue; //var has a name, skip now
			}
			if (0 == wcscmp(pvOwnEnvArray[j].pwszVarValue, pvProcessEnvArray[i].pwszVarValue))
			{
				bFound = TRUE;
				break; //same nameless var found, no need to add to diff
			}
		}
		if (!bFound)
		{
			//not found in process nameless vars
			HRESULT hResult;
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t- ");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"=");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvOwnEnvArray[j].pwszVarValue);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\r\n");
			CHECKSTRINGHR(hResult);
			ResizeWcharBufIfNeeded(&pwszDiffStr, &stDiffBufSize);
		}
	}

	//named vars now
	for (DWORD i = 0; i < dwProcessEnvEntryCount; i++)
	{
		if (0 == wcslen(pvProcessEnvArray[i].pwszVarName))
		{
			continue; //env vars like "=C:" can exist, skip them now
		}

		BOOL bNameFound;
		bNameFound = FALSE;
		for (DWORD j = 0; j < dwOwnEnvEntryCount; j++)
		{
			if (0 == _wcsicmp(pvProcessEnvArray[i].pwszVarName, pvOwnEnvArray[j].pwszVarName))
			{
				bNameFound = TRUE;

				//found matching name. check value
				if (0 == wcscmp(pvProcessEnvArray[i].pwszVarValue, pvOwnEnvArray[j].pwszVarValue))
				{
					break; //same value, no need to add to diff
				}

				bNoDiff = FALSE;
				//same name, different value.
				HRESULT hResult;
				hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t~ ");
				CHECKSTRINGHR(hResult);
				hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvProcessEnvArray[i].pwszVarName);
				CHECKSTRINGHR(hResult);
				hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"=");
				CHECKSTRINGHR(hResult);
				hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvProcessEnvArray[i].pwszVarValue);
				CHECKSTRINGHR(hResult);
				hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\r\n");
				CHECKSTRINGHR(hResult);
				ResizeWcharBufIfNeeded(&pwszDiffStr, &stDiffBufSize);
			}
		} //for j

		if (!bNameFound)
		{
			//another process has it, own does not. add to diff
			bNoDiff = FALSE;
			HRESULT hResult;
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t+ ");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvProcessEnvArray[i].pwszVarName);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"=");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvProcessEnvArray[i].pwszVarValue);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\r\n");
			CHECKSTRINGHR(hResult);
			ResizeWcharBufIfNeeded(&pwszDiffStr, &stDiffBufSize);
		}
	} //for i

	//check for vars that exist in own, but not in process
	for (DWORD j = 0; j < dwOwnEnvEntryCount; j++)
	{
		if (0 == wcslen(pvOwnEnvArray[j].pwszVarName))
		{
			continue; //env vars like "=C:" can exist, skip them now
		}

		BOOL bNameFound = FALSE;
		for (DWORD i = 0; i < dwProcessEnvEntryCount; i++)
		{
			if (0 == wcscmp(pvOwnEnvArray[j].pwszVarName, pvProcessEnvArray[i].pwszVarName))
			{
				bNameFound = TRUE;
				break;
			}
		}
		if (!bNameFound)
		{
			//own has it, another process does not. add to diff
			bNoDiff = FALSE;
			HRESULT hResult;
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t- ");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvOwnEnvArray[j].pwszVarName);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"=");
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), pvOwnEnvArray[j].pwszVarValue);
			CHECKSTRINGHR(hResult);
			hResult = StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\r\n");
			CHECKSTRINGHR(hResult);
			ResizeWcharBufIfNeeded(&pwszDiffStr, &stDiffBufSize);
		}
	}

	if (bNoDiff)
	{
		StringCchCatW(pwszDiffStr, stDiffBufSize / sizeof(WCHAR), L"\t(no differences)\r\n");
	}

	SETCleanEnvArray(pvProcessEnvArray, dwProcessEnvEntryCount);
	ShrinkWcharBuffer(&pwszDiffStr);
	return pwszDiffStr;
}


PWSTR SETGetOwnEnv(void)
{
	PWSTR pwszOwnEnv; //buffer to return
	PWSTR pwszFullEnvOrg; //full env block
	pwszFullEnvOrg = GetEnvironmentStringsW();

	dwOwnEnvEntryCount = SETEnvBlockToArray(pwszFullEnvOrg, &pvOwnEnvArray);

	pwszOwnEnv = SETEnvBlockToString((PVOID)pwszFullEnvOrg);
	FreeEnvironmentStringsW(pwszFullEnvOrg);
	return pwszOwnEnv;
}


BOOL SETGetProcessData(HANDLE hProcessHandle, PWSTR* ppwszImage, PWSTR* ppwszEnvironment)
{
	PEB Peb = {0}; //800 Bytes
	PROCESS_BASIC_INFORMATION basicInfo = {0};
	NTSTATUS status;

	size_t dwDataTempBytes = SIZE_1KB;
	PWSTR pwszDataTemp;
	ALLOCORCRASH(pwszDataTemp, dwDataTempBytes);

	BOOL bRes;

	// Get the process info.
	status = NtQueryInformationProcess(hProcessHandle, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);

	if (0 != status)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"(ERROR: %i, NtQueryInformationProcess)",
			status);
		ShrinkWcharBuffer(&pwszDataTemp);
		*ppwszImage = pwszDataTemp;
		*ppwszEnvironment = NULL;
		return FALSE;
	}

	bRes = FALSE;
	if (NULL != basicInfo.PebBaseAddress)
	{
		bRes = ReadProcessMemory(hProcessHandle, basicInfo.PebBaseAddress, &Peb, sizeof(PEB), NULL);
	}
	if (!bRes)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"(ERROR: %i, ReadProcessMemory PEB)",
			GetLastError());
		ShrinkWcharBuffer(&pwszDataTemp);
		*ppwszImage = pwszDataTemp;
		*ppwszEnvironment = NULL;
		return FALSE;
	}

	RTL_USER_PROCESS_PARAMETERS upp = {0};
	bRes = ReadProcessMemory(hProcessHandle, (LPCVOID)Peb.ProcessParameters, &upp, sizeof(upp), NULL);
	if (!bRes)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"(ERROR: %i, ReadProcessMemory ProcessParameters)",
			GetLastError());
		ShrinkWcharBuffer(&pwszDataTemp);
		*ppwszImage = pwszDataTemp;
		*ppwszEnvironment = NULL;
		return FALSE;
	}


	PWSTR pwszImage;
	ALLOCORCRASH(pwszImage, (upp.ImagePathName.Length + sizeof(WCHAR)));
	bRes = FALSE;
	if (NULL != upp.ImagePathName.Buffer)
	{
		bRes = ReadProcessMemory(hProcessHandle, upp.ImagePathName.Buffer, pwszImage, upp.ImagePathName.Length, NULL);
	}
	if (!bRes)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"(ERROR: %i, ReadProcessMemory ImagePathName)",
			GetLastError());
		ShrinkWcharBuffer(&pwszDataTemp);
		*ppwszImage = pwszDataTemp;
		*ppwszEnvironment = NULL;
		LocalFree(pwszImage);
		pwszImage = NULL;
		//return FALSE; //do not return, try to get env anyway
	}
	*ppwszImage = pwszImage;

	PWSTR pwszEnv;
	ALLOCORCRASH(pwszEnv, upp.EnvironmentSize);
	bRes = ReadProcessMemory(hProcessHandle, upp.Environment, pwszEnv, (SIZE_T)upp.EnvironmentSize, NULL);
	if (!bRes)
	{
		StringCchPrintfW(
			pwszDataTemp,
			dwDataTempBytes / sizeof(WCHAR),
			L"(ERROR: %i, ReadProcessMemory Environment)",
			GetLastError());
		ShrinkWcharBuffer(&pwszDataTemp);
		*ppwszImage = pwszImage;
		*ppwszEnvironment = pwszDataTemp;
		LocalFree(pwszEnv);
		return FALSE;
	}

	*ppwszEnvironment = pwszEnv;

	LocalFree(pwszDataTemp);
	return TRUE;
}


BOOL SETMain(void)
{
	HRESULT hResult;

	//own env
	StringCchCatW(pwszSetBuf, stSetBufSize, L"-1:\tGetCurrentProcess().GetEnvironmentStringsW()\r\n");
	PWSTR pwszOwnEnv;
	pwszOwnEnv = SETGetOwnEnv();
	hResult = StringCchCatW(pwszSetBuf, stSetBufSize / sizeof(WCHAR), pwszOwnEnv);
	CHECKSTRINGHR(hResult);
	LocalFree(pwszOwnEnv);

	//all process envs
	// Get the list of process identifiers.
	DWORD cbNeeded;
	DWORD cProcesses;
	DWORD i;
	DWORD dwProcArrSize;
	PDWORD pdwProcArr;
	HANDLE hProcessHandle;

	dwProcArrSize = INITIAL_PROCESS_COUNT * sizeof(DWORD);
	pdwProcArr = (PDWORD)LocalAlloc(LPTR, dwProcArrSize);
	CRASHIFNULLALLOC(pdwProcArr);

	EnumProcesses(pdwProcArr, dwProcArrSize, &cbNeeded);
	while (dwProcArrSize == cbNeeded)
	{
		LocalFree(pdwProcArr);
		dwProcArrSize *= 2;
		pdwProcArr = (PDWORD)LocalAlloc(LPTR, dwProcArrSize);
		CRASHIFNULLALLOC(pdwProcArr);
		EnumProcesses(pdwProcArr, dwProcArrSize, &cbNeeded);
	}
	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		hProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pdwProcArr[i]);

		if (NULL != hProcessHandle) //process opened
		{
			size_t stPathDataSize;
			stPathDataSize = NT_MAX_PATH * sizeof(WCHAR);

			PWSTR pwszProcessImage = NULL;
			PWSTR pwszProcessEnv = NULL;

			SETGetProcessData(hProcessHandle, &pwszProcessImage, &pwszProcessEnv);
			if (!pwszProcessImage)
			{
				ALLOCORCRASH(pwszProcessImage, SIZE_1KB);
				StringCchPrintfW(pwszProcessImage, LocalSize(pwszProcessImage) / sizeof(WCHAR), L"(Cannot get image)");
			}

			PWSTR pwszProcessStr;
			ALLOCORCRASH(pwszProcessStr, (stPathDataSize + SIZE_1KB));

			StringCchPrintfW(
				pwszProcessStr,
				LocalSize(pwszProcessStr) / sizeof(WCHAR),
				L"%i:\t%s\r\n",
				pdwProcArr[i],
				pwszProcessImage);
			StringCchCatW(pwszSetBuf, stSetBufSize, pwszProcessStr);
			LocalFree(pwszProcessStr);

			if (pwszProcessEnv)
			{
				PWSTR pwszEnvString;
				pwszEnvString = SETEnvBlockToDiffString((PVOID)pwszProcessEnv);
				LocalFree(pwszProcessEnv);
				pwszProcessEnv = pwszEnvString;
			}
			else
			{
				ALLOCORCRASH(pwszProcessEnv, SIZE_1KB);
				StringCchPrintfW(
					pwszProcessEnv,
					LocalSize(pwszProcessEnv) / sizeof(WCHAR),
					L"\t(Cannot get environment)\r\n");
			}

			StringCchCatW(pwszSetBuf, stSetBufSize, pwszProcessEnv);

			LocalFree(pwszProcessImage);
			LocalFree(pwszProcessEnv);
			CloseHandle(hProcessHandle);
			ResizeWcharBufIfNeeded(&pwszSetBuf, &stSetBufSize);
		}
		else //cant open process
		{
			PWSTR pwszError;
			DWORD dwLastError;
			dwLastError = GetLastError();

			ALLOCORCRASH(pwszError, SIZE_1KB);
			StringCchPrintfW(
				pwszError,
				LocalSize(pwszError) / sizeof(WCHAR),
				L"%i:\t(ERROR: %i, OpenProcess)\r\n",
				pdwProcArr[i],
				dwLastError);
			StringCchCatW(pwszSetBuf, stSetBufSize, pwszError);

			StringCchPrintfW(pwszError, LocalSize(pwszError) / sizeof(WCHAR), L"\t(Cannot get environment)\r\n");
			StringCchCatW(pwszSetBuf, stSetBufSize, pwszError);
			LocalFree(pwszError);
		}
		ResizeWcharBufIfNeeded(&pwszSetBuf, &stSetBufSize);
	}

	SETCleanEnvArray(pvOwnEnvArray, dwOwnEnvEntryCount);

	LocalFree(pdwProcArr);
	return TRUE;
}


PWSTR SET_Output(void)
{
	wprintf(L"Listing Environment\r\n");

	stSetBufSize = SIZE_1MB;
	pwszSetBuf = (PWSTR)LocalAlloc(LPTR, stSetBufSize);
	CRASHIFNULLALLOC(pwszSetBuf);

	AddCheckHeader(pwszSetBuf, stSetBufSize, L"Environment Variables", TRUE);

	SETMain();

	ShrinkWcharBuffer(&pwszSetBuf);
	return pwszSetBuf;
}
