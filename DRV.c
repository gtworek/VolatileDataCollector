#include "VSTriage.h"

PWSTR pwszDrvBuf = NULL;
size_t stDrvBufSize;

BOOL DRVMain(void)
{
	LPVOID* pDriversTable;
	DWORD dwDriversTableSize;
	DWORD dwDriverCount;
	DWORD dwLastError;
	BOOL bRes;
	BOOL bSuccess = TRUE;

	pDriversTable = NULL;
	dwDriversTableSize = sizeof(LPVOID); //init 1, 0 changes the result.

	while (TRUE)
	{
		DWORD dwRequiredTableSize;
		if (pDriversTable)
		{
			LocalFree(pDriversTable);
		}
		pDriversTable = LocalAlloc(LPTR, dwDriversTableSize);
		CRASHIFNULLALLOC(pDriversTable);
		bRes = EnumDeviceDrivers(pDriversTable, dwDriversTableSize, &dwRequiredTableSize);
		if (bRes)
		{
			if (dwDriversTableSize == dwRequiredTableSize)
			{
				break; //done
			}
			else
			{
				dwDriversTableSize = dwRequiredTableSize;
				continue;
			}
		}
		else
		{
			dwLastError = GetLastError();
			REPORTERROR(L"EnumDeviceDrivers() failed ", dwLastError);
			bSuccess = FALSE;
			break;
		}
	}

	if (0 == dwDriversTableSize)
	{
		return FALSE;
	}

	dwDriverCount = dwDriversTableSize / sizeof(LPVOID);
	for (DWORD i = 0; i < dwDriverCount; i++)
	{
		TCHAR szDriver[MAX_PATH];
		LPVOID pCurrentDriver = pDriversTable[i];
		if (GetDeviceDriverFileNameW(pCurrentDriver, szDriver, ARRAYSIZE(szDriver)))
		{
			WCHAR wszDrivers[MAX_PATH] = {0};
			StringCchPrintfW(wszDrivers, ARRAYSIZE(wszDrivers), L"%s\r\n", szDriver);
			StringCchCatW(pwszDrvBuf, stDrvBufSize / sizeof(WCHAR), wszDrivers);
		}
		else
		{
			bSuccess = FALSE;
		}
	}
	LocalFree(pDriversTable);

	if (!bSuccess)
	{
		StringCchCatW(
			pwszDrvBuf,
			stDrvBufSize / sizeof(WCHAR),
			L"(Results may be incomplete due to failed API calls.)\r\n");
	}

	return TRUE;
}


PWSTR DRV_Output(void)
{
	wprintf(L"Listing Drivers\r\n");
	stDrvBufSize = SIZE_16MB;

	pwszDrvBuf = LocalAlloc(LPTR, stDrvBufSize);
	CRASHIFNULLALLOC(pwszDrvBuf);

	AddCheckHeader(pwszDrvBuf, stDrvBufSize, L"Drivers", TRUE);

	DRVMain();
	ShrinkWcharBuffer(&pwszDrvBuf);
	return pwszDrvBuf;
}
