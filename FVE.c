#include "VSTriage.h"

PWSTR pwszFVEBuf = NULL;
size_t stFVEBufSize;
HMODULE hFveApiDLL;

PWSTR pwszKeyProtectors[] = {
	L"", L"Recovery Password", L"PIN", L"TPM", L"External Key", L"", L"", L"", L"Passphrase", L"Clear Key", L"DPAPI-NG",
	L"Network", L""
};


typedef HRESULT (NTAPI*FVESETALLOWKEYEXPORT)(BOOL);

HRESULT NTAPI FveSetAllowKeyExport(BOOL Allow)
{
	static FVESETALLOWKEYEXPORT pfnFveSetAllowKeyExport = NULL;
	if (NULL == pfnFveSetAllowKeyExport)
	{
		pfnFveSetAllowKeyExport = (FVESETALLOWKEYEXPORT)(LPVOID)GetProcAddress(hFveApiDLL, "FveSetAllowKeyExport");
	}
	if (NULL == pfnFveSetAllowKeyExport)
	{
		REPORTERROR(L"FveSetAllowKeyExport failed", GetLastError());
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	}
	return pfnFveSetAllowKeyExport(Allow);
}


typedef HRESULT (NTAPI*FVEOPENVOLUMEW)(PCWSTR, BOOL, HANDLE*);

HRESULT NTAPI FveOpenVolumeW(PCWSTR VolumeName, BOOL bNeedWriteAccess, HANDLE* phVolume)
{
	static FVEOPENVOLUMEW pfnFveOpenVolumeW = NULL;
	if (NULL == pfnFveOpenVolumeW)
	{
		pfnFveOpenVolumeW = (FVEOPENVOLUMEW)(LPVOID)GetProcAddress(hFveApiDLL, "FveOpenVolumeW");
	}
	if (NULL == pfnFveOpenVolumeW)
	{
		REPORTERROR(L"FveOpenVolumeW failed", GetLastError());
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	}
	return pfnFveOpenVolumeW(VolumeName, bNeedWriteAccess, phVolume);
}


typedef HRESULT (NTAPI*FVEGETAUTHMETHODGUIDS)(HANDLE, LPGUID, UINT, PUINT);

HRESULT NTAPI FveGetAuthMethodGuids(HANDLE hFveVolume, LPGUID AuthMethodGuids, UINT MaxNumGuids, PUINT NumGuids)

{
	static FVEGETAUTHMETHODGUIDS pfnFveGetAuthMethodGuids = NULL;
	if (NULL == pfnFveGetAuthMethodGuids)
	{
		pfnFveGetAuthMethodGuids = (FVEGETAUTHMETHODGUIDS)(LPVOID)GetProcAddress(hFveApiDLL, "FveGetAuthMethodGuids");
	}
	if (NULL == pfnFveGetAuthMethodGuids)
	{
		REPORTERROR(L"FveGetAuthMethodGuids failed", GetLastError());
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	}
	return pfnFveGetAuthMethodGuids(hFveVolume, AuthMethodGuids, MaxNumGuids, NumGuids);
}


typedef HRESULT (*FVEGETAUTHMETHODINFORMATION)(HANDLE, PMY_AUTH_INFORMATION, SIZE_T, SIZE_T*);

HRESULT FveGetAuthMethodInformation(
	HANDLE hFveVolume,
	PMY_AUTH_INFORMATION Information,
	SIZE_T BufferSize,
	SIZE_T* RequiredSize
)
{
	static FVEGETAUTHMETHODINFORMATION pfnFveGetAuthMethodInformation = NULL;
	if (NULL == pfnFveGetAuthMethodInformation)
	{
		pfnFveGetAuthMethodInformation = (FVEGETAUTHMETHODINFORMATION)(LPVOID)GetProcAddress(
			hFveApiDLL,
			"FveGetAuthMethodInformation");
	}
	if (NULL == pfnFveGetAuthMethodInformation)
	{
		REPORTERROR(L"FveGetAuthMethodInformation failed", GetLastError());
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	}
	return pfnFveGetAuthMethodInformation(hFveVolume, Information, BufferSize, RequiredSize);
}


typedef HRESULT (*FVECLOSEVOLUME)(HANDLE);

HRESULT FveCloseVolume(HANDLE FveVolumeHandle)
{
	static FVECLOSEVOLUME pfnFveCloseVolume = NULL;
	if (NULL == pfnFveCloseVolume)
	{
		pfnFveCloseVolume = (FVECLOSEVOLUME)(LPVOID)GetProcAddress(hFveApiDLL, "FveCloseVolume");
	}
	if (NULL == pfnFveCloseVolume)
	{
		REPORTERROR(L"FveCloseVolume failed", GetLastError());
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
	}
	return pfnFveCloseVolume(FveVolumeHandle);
}


VOID FVEBin2StrW(PWSTR pwszBuffer, PBYTE pbData)
{
	WCHAR pwszTemp[8] = {0};

	for (int j = 0; j < 8; j++)
	{
		UINT uBlock;
		uBlock = *(PBYTE)(Add2Ptr(pbData, j * 2 + 1));
		uBlock *= 256;
		uBlock += *(PBYTE)(Add2Ptr(pbData, j * 2));
		uBlock *= 11;

		StringCchPrintfW(pwszTemp, _ARRAYSIZE(pwszTemp), L"%06d", uBlock);
		StringCchCatW(pwszBuffer, LocalSize(pwszBuffer), pwszTemp);
		if (j < 7)
		{
			StringCchCatW(pwszBuffer, LocalSize(pwszBuffer), L"-");
		}
	}
}

PWSTR FVEGetKeys(PWSTR pwszVolumeName)
{
	HRESULT hr;
	HANDLE hFveVolume;

	PWSTR pwszAllKeys;
	PWSTR pwszTemp1;
	PWSTR pwszTemp2;
	SIZE_T stAllKeysSize = SIZE_1MB;

	ALLOCORCRASH(pwszAllKeys, stAllKeysSize);

	hr = FveOpenVolumeW(pwszVolumeName, FALSE, &hFveVolume);
	if (FAILED(hr))
	{
		//normal thing. Log but don't report.
		StringCchPrintfW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), L"\t(ERROR 0x%08x)\r\n", hr);
		return pwszAllKeys;
	}

	UINT dwGuidCount = 0;
	LPGUID pGuids;

	hr = FveGetAuthMethodGuids(hFveVolume, NULL, 0, &dwGuidCount);
	if (FAILED(hr))
	{
		if (FVE_E_NOT_ACTIVATED == hr)
		{
			StringCchPrintfW(
				pwszAllKeys,
				stAllKeysSize / sizeof(WCHAR),
				L"\t(BitLocker Drive Encryption is not enabled on this drive.)\r\n");
			FveCloseVolume(hFveVolume);
			return pwszAllKeys;
		}
		//fail
		REPORTERROR(L"FveGetAuthMethodGuids failed", hr);
		StringCchPrintfW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), L"\t(ERROR 0x%08x)\r\n", hr);
		FveCloseVolume(hFveVolume);
		return pwszAllKeys;
	}
	ALLOCORCRASH(pGuids, dwGuidCount * sizeof(GUID));

	hr = FveGetAuthMethodGuids(hFveVolume, pGuids, dwGuidCount, &dwGuidCount);
	if (FAILED(hr))
	{
		REPORTERROR(L"FveGetAuthMethodGuids failed", hr);
		StringCchPrintfW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), L"\t(ERROR 0x%08x)\r\n", hr);
		LocalFree(pGuids);
		return pwszAllKeys;
	}

	for (DWORD i = 0; i < dwGuidCount; i++)
	{
		ALLOCORCRASH(pwszTemp1, SIZE_1KB);
		StringCchPrintfW(
			pwszTemp1,
			LocalSize(pwszTemp1) / sizeof(WCHAR),
			L"\tKey Id: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\r\n",
			pGuids[i].Data1,
			pGuids[i].Data2,
			pGuids[i].Data3,
			pGuids[i].Data4[0],
			pGuids[i].Data4[1],
			pGuids[i].Data4[2],
			pGuids[i].Data4[3],
			pGuids[i].Data4[4],
			pGuids[i].Data4[5],
			pGuids[i].Data4[6],
			pGuids[i].Data4[7]);
		StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
		LocalFree(pwszTemp1);

		MY_AUTH_INFORMATION FveAuthInfo = {0};
		PMY_AUTH_INFORMATION pFveAuthInfo1;
		SIZE_T cbRequiredSize;

		FveAuthInfo.Size    = sizeof(MY_AUTH_INFORMATION);
		FveAuthInfo.Version = 1;
		FveAuthInfo.Flags   = 1;
		FveAuthInfo.Guid    = pGuids[i];

		pFveAuthInfo1 = &FveAuthInfo;

		hr = FveGetAuthMethodInformation(hFveVolume, pFveAuthInfo1, sizeof(MY_AUTH_INFORMATION), &cbRequiredSize);
		if (FAILED(hr) && HRESULT_CODE(hr) != ERROR_INSUFFICIENT_BUFFER)
		{
			REPORTERROR(L"FveGetAuthMethodInformation failed", hr);
			StringCchPrintfW(pwszTemp1, LocalSize(pwszTemp1) / sizeof(WCHAR), L"\t\t(ERROR 0x%08x)\r\n", hr);
			StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
			LocalFree(pwszTemp1);
			continue;
		}

		ALLOCORCRASH(pFveAuthInfo1, cbRequiredSize);

		pFveAuthInfo1->Size    = FveAuthInfo.Size;
		pFveAuthInfo1->Version = FveAuthInfo.Version;
		pFveAuthInfo1->Flags   = FveAuthInfo.Flags;
		pFveAuthInfo1->Guid    = FveAuthInfo.Guid;

		hr = FveGetAuthMethodInformation(hFveVolume, pFveAuthInfo1, cbRequiredSize, &cbRequiredSize);
		if (FAILED(hr))
		{
			REPORTERROR(L"FveGetAuthMethodInformation failed", hr);
			StringCchPrintfW(pwszTemp1, LocalSize(pwszTemp1) / sizeof(WCHAR), L"\t\t(ERROR 0x%08x)\r\n", hr);
			StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
			LocalFree(pwszTemp1);
			continue;
		}

		ALLOCORCRASH(pwszTemp1, SIZE_1KB);
		SYSTEMTIME stCreationTime;
		FILETIME ftCreationTime;
		PWSTR pwszCreationTime;
		ftCreationTime.dwLowDateTime  = pFveAuthInfo1->CreationTime.dwLowDateTime;
		ftCreationTime.dwHighDateTime = pFveAuthInfo1->CreationTime.dwHighDateTime;
		FileTimeToSystemTime(&ftCreationTime, &stCreationTime);
		pwszCreationTime = SystemTimeToISO8601(stCreationTime);
		StringCchPrintfW(
			pwszTemp1,
			LocalSize(pwszTemp1) / sizeof(WCHAR),
			L"\t\tCreationTime: %s\r\n",
			pwszCreationTime);
		StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
		LocalFree(pwszCreationTime);

		if (pFveAuthInfo1->Description)
		{
			StringCchPrintfW(
				pwszTemp1,
				LocalSize(pwszTemp1) / sizeof(WCHAR),
				L"\t\tDescription: %s\r\n",
				pFveAuthInfo1->Description);
			StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
		}

		LocalFree(pwszTemp1);

		//go through elements, display type, if 1 display data
		for (DWORD j = 0; j < pFveAuthInfo1->ElementsCount; j++)
		{
			ALLOCORCRASH(pwszTemp1, SIZE_1KB);
			StringCchPrintfW(
				pwszTemp1,
				LocalSize(pwszTemp1) / sizeof(WCHAR),
				L"\t\t\t[%03d] Type: %d %s\r\n",
				j + 1,
				pFveAuthInfo1->Elements[j]->Type,
				pwszKeyProtectors[pFveAuthInfo1->Elements[j]->Type]);
			StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
			LocalFree(pwszTemp1);

			if (1 == pFveAuthInfo1->Elements[j]->Type)
			{
				PMY_AUTH_INFORMATION pFveAuthInfo2;
				ALLOCORCRASH(pFveAuthInfo2, sizeof(MY_AUTH_INFORMATION));
				pFveAuthInfo2->Size    = sizeof(MY_AUTH_INFORMATION);
				pFveAuthInfo2->Version = 1;
				pFveAuthInfo2->Flags   = FVE_GET_PASSWORD_FLAGS;
				pFveAuthInfo2->Guid    = pGuids[i];

				hr = FveGetAuthMethodInformation(
					hFveVolume,
					pFveAuthInfo2,
					sizeof(MY_AUTH_INFORMATION),
					&cbRequiredSize);
				if (FAILED(hr) && HRESULT_CODE(hr) != ERROR_INSUFFICIENT_BUFFER)
				{
					ALLOCORCRASH(pwszTemp1, SIZE_1KB);
					StringCchPrintfW(
						pwszTemp1,
						LocalSize(pwszTemp1) / sizeof(WCHAR),
						L"\t\t\t[%03d] Password: (ERROR 0x%08x)\r\n",
						j + 1,
						hr);
					StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
					LocalFree(pwszTemp1);
					LocalFree(pFveAuthInfo2);
					continue;
				}
				LocalFree(pFveAuthInfo2);

				ALLOCORCRASH(pFveAuthInfo2, cbRequiredSize);
				pFveAuthInfo2->Size    = sizeof(MY_AUTH_INFORMATION);
				pFveAuthInfo2->Version = 1;
				pFveAuthInfo2->Flags   = FVE_GET_PASSWORD_FLAGS;
				pFveAuthInfo2->Guid    = pGuids[i];

				hr = FveGetAuthMethodInformation(hFveVolume, pFveAuthInfo2, cbRequiredSize, &cbRequiredSize);
				if (FAILED(hr))
				{
					REPORTERROR(L"FveGetAuthMethodInformation failed", hr);
					ALLOCORCRASH(pwszTemp1, SIZE_1KB);
					StringCchPrintfW(
						pwszTemp1,
						LocalSize(pwszTemp1) / sizeof(WCHAR),
						L"\t\t\t[%03d] Password: (ERROR 0x%08x)\r\n",
						j + 1,
						hr);
					StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp1);
					LocalFree(pwszTemp1);
					LocalFree(pFveAuthInfo2);
					continue;
				}

				//got the key
				ALLOCORCRASH(pwszTemp1, SIZE_1KB);
				ALLOCORCRASH(pwszTemp2, SIZE_1KB);
				FVEBin2StrW(pwszTemp1, (PBYTE)&pFveAuthInfo2->Elements[j]->Data);
				StringCchPrintfW(
					pwszTemp2,
					LocalSize(pwszTemp2) / sizeof(WCHAR),
					L"\t\t\t[%03d] Password: %s\r\n",
					j + 1,
					pwszTemp1);
				StringCchCatW(pwszAllKeys, stAllKeysSize / sizeof(WCHAR), pwszTemp2);
				LocalFree(pFveAuthInfo2);
				LocalFree(pwszTemp2);
				LocalFree(pwszTemp1);
			}
		}
		LocalFree(pFveAuthInfo1);
		ResizeWcharBufIfNeeded(&pwszAllKeys, &stAllKeysSize);
	}
	LocalFree(pGuids);
	FveCloseVolume(hFveVolume);
	return pwszAllKeys;
}


BOOL FVEMain(void)
{
	DWORD charCount            = MAX_PATH; //51 actually
	WCHAR volumeName[MAX_PATH] = {0};
	WCHAR wszPart[SIZE_1KB]    = {0};
	HANDLE findHandle;

	HRESULT hr;
	hr = FveSetAllowKeyExport(TRUE);
	if (FAILED(hr))
	{
		//report but keep trying anyway as some result may be useful
		REPORTERROR(L"FveSetAllowKeyExport failed", hr);
	}

	findHandle = FindFirstVolumeW(volumeName, charCount);

	if (INVALID_HANDLE_VALUE == findHandle)
	{
		StringCchPrintfW(wszPart, _ARRAYSIZE(wszPart), L"(ERROR: %lu)", GetLastError());
		StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), wszPart);
		wprintf(L" (some errors)\r\n");
		REPORTERROR(L"FindFirstVolumeW() failed ", GetLastError());
		return FALSE;
	}

	do
	{
		// volume name
		StringCchPrintfW(wszPart, _ARRAYSIZE(wszPart), L"Volume: %s\t", volumeName);
		StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), wszPart);

		DWORD cbAllocated;
		DWORD cbNeeded        = 5; //enough for typical single letter mount points "C:\#0#0"
		LPWCH pwszVolumePaths = NULL;
		BOOL bRes;

		do
		{
			cbAllocated = cbNeeded;
			cbNeeded    = 0;
			LocalFree(pwszVolumePaths);
			ALLOCORCRASH(pwszVolumePaths, cbAllocated * sizeof(WCHAR));
			bRes = GetVolumePathNamesForVolumeNameW(volumeName, pwszVolumePaths, cbAllocated, &cbNeeded);
			if (!bRes)
			{
				DWORD dwError = GetLastError();
				if (dwError != ERROR_MORE_DATA)
				{
					REPORTERROR(L"GetVolumePathNamesForVolumeNameW() failed ", dwError);
					break;
				}
			}
		}
		while (cbNeeded != cbAllocated);

		if (cbAllocated > 1)
		{
			LPWCH pwszCurrentPath = pwszVolumePaths;

			//iterate through the mount points separated by #0 and concat them with commas
			while (*pwszCurrentPath)
			{
				StringCchPrintfW(wszPart, _ARRAYSIZE(wszPart), L"%s", pwszCurrentPath);
				StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), wszPart);

				pwszCurrentPath += lstrlenW(pwszCurrentPath) + 1;
				if (*pwszCurrentPath)
				{
					StringCchPrintfW(wszPart, _ARRAYSIZE(wszPart), L", ");
					StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), wszPart);
				}
			}
		}
		else
		{
			// no mount points
			StringCchPrintfW(wszPart, _ARRAYSIZE(wszPart), L"*** NO MOUNT POINTS ***");
			StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), wszPart);
		}

		StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), L"\r\n");
		ResizeWcharBufIfNeeded(&pwszFVEBuf, &stFVEBufSize);

		LocalFree(pwszVolumePaths);

		PWCHAR pwszKeys;
		pwszKeys = FVEGetKeys(volumeName);
		StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), pwszKeys);
		LocalFree(pwszKeys);


		// Proceed to the next volume
		bRes = FindNextVolumeW(findHandle, volumeName, charCount);
		if (!bRes)
		{
			DWORD dwError = GetLastError();
			if (dwError != ERROR_NO_MORE_FILES)
			{
				REPORTERROR(L"FindNextVolumeW() failed ", dwError);
				FindVolumeClose(findHandle);
				return FALSE;
			}
			break; // No more volumes
		}
	}
	while (TRUE);

	FindVolumeClose(findHandle);
	return TRUE;
}


PWSTR FVE_Output(void)
{
	wprintf(L"Listing BitLocker keys\r\n");
	stFVEBufSize = SIZE_1MB;
	ALLOCORCRASH(pwszFVEBuf, stFVEBufSize);

	AddCheckHeader(pwszFVEBuf, stFVEBufSize, L"BitLocker Keys", FALSE);

	hFveApiDLL = LoadLibraryExW(L"fveapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (NULL == hFveApiDLL)
	{
		DWORD dwError;
		dwError = GetLastError();
		REPORTERROR(L"LoadLibraryEx() failed ", dwError);
		PWSTR pwszTemp;
		ALLOCORCRASH(pwszTemp, SIZE_1KB);
		StringCchPrintfW(pwszTemp, LocalSize(pwszTemp) / sizeof(WCHAR), L"(ERROR %lu)\r\n", dwError);
		StringCchCatW(pwszFVEBuf, stFVEBufSize / sizeof(WCHAR), pwszTemp);
		LocalFree(pwszTemp);
	}
	else
	{
		FVEMain();
		FreeLibrary(hFveApiDLL);
	}

	ShrinkWcharBuffer(&pwszFVEBuf);
	wprintf(L"\r\n");
	return pwszFVEBuf;
}
