#include "VSTriage.h"

PWSTR pwszHNMBuf = NULL;
size_t stHNMBufSize;

PWSTR pwszNameFormats[ComputerNameMax] = {
	L"ComputerNameNetBIOS",
	L"ComputerNameDnsHostname",
	L"ComputerNameDnsDomain",
	L"ComputerNameDnsFullyQualified",
	L"ComputerNamePhysicalNetBIOS",
	L"ComputerNamePhysicalDnsHostname",
	L"ComputerNamePhysicalDnsDomain",
	L"ComputerNamePhysicalDnsFullyQualified"
};


BOOL IsAdmin(void)
{
	BOOL IsMember;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
	PSID AdminSid;

	if (!AllocateAndInitializeSid(
		&sia,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0,
		0,
		0,
		0,
		0,
		0,
		&AdminSid))
	{
		return FALSE;
	}
	if (!CheckTokenMembership(
		NULL,
		AdminSid,
		&IsMember))
	{
		//fail. Taking this as FALSE.
		FreeSid(AdminSid);
		return FALSE;
	}
	FreeSid(AdminSid);
	return IsMember;
}


BOOL HNMMain(void)
{
	PWSTR pwszTemp;
	PWSTR pwszData;
	size_t stTempWchars;
	size_t stDataSize;
	stTempWchars = SIZE_1MB;
	stDataSize = SIZE_1MB;
	BOOL bRes;
	DWORD dwChars;

	ALLOCORCRASH(pwszTemp, stTempWchars * sizeof(WCHAR));
	//CRASHORALLOC(pwszData, stDataSize);
	pwszData = LocalAlloc(LPTR, stDataSize);
	CRASHIFNULLALLOC(pwszData);

	//whoami
	pwszData[0] = L'\0';
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), L"User:\r\n");
	dwChars = (DWORD)stTempWchars;
	bRes = GetUserNameExW(NameSamCompatible, pwszTemp, &dwChars);
	if (!bRes)
	{
		StringCchPrintfW(pwszTemp, stTempWchars, L"(ERROR %i)\r\n", GetLastError());
	}
	StringCchPrintfW(pwszData, stDataSize / sizeof(WCHAR), L"\tName: %s\r\n", pwszTemp);
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszData);

	StringCchPrintfW(pwszData, stDataSize / sizeof(WCHAR), L"\tAdmin: ");
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), IsAdmin() ? L"Yes" : L"No");
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), L"\r\n");
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszData);


	//names
	pwszData[0] = L'\0';
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), L"Hostname:\r\n");
	for (DWORD i = 0; i < ComputerNameMax; i++)
	{
		dwChars = (DWORD)stTempWchars;

		bRes = GetComputerNameExW((COMPUTER_NAME_FORMAT)i, pwszTemp, &dwChars);
		if (!bRes)
		{
			StringCchPrintfW(pwszTemp, stTempWchars, L"(ERROR %i)\r\n", GetLastError());
		}
		if (0 != wcsnlen(pwszTemp, stTempWchars))
		{
			StringCchPrintfW(pwszData, stDataSize / sizeof(WCHAR), L"\t%s: ", pwszNameFormats[i]);
			StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);
			StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), L"\r\n");
			StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszData);
		}
	}

	//osver
	pwszData[0] = L'\0';
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), L"Version:\r\n");
	RTL_OSVERSIONINFOEXW rosvInfo = {0};

	rosvInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&rosvInfo);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tMajorVersion: %lu\r\n", rosvInfo.dwMajorVersion);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tMinorVersion: %lu\r\n", rosvInfo.dwMinorVersion);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tBuildNumber: %lu\r\n", rosvInfo.dwBuildNumber);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	if (0 != wcsnlen(rosvInfo.szCSDVersion, ARRAYSIZE(rosvInfo.szCSDVersion)))
	{
		StringCchPrintfW(pwszTemp, stTempWchars, L"\tCSDVersion: %s\r\n", rosvInfo.szCSDVersion);
		StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);
	}

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tServicePackMajor: %lu\r\n", rosvInfo.wServicePackMajor);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tServicePackMinor: %lu\r\n", rosvInfo.wServicePackMinor);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tMajorVersion: 0x%08x\r\n", rosvInfo.wSuiteMask);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);

	StringCchPrintfW(pwszTemp, stTempWchars, L"\tProductType: 0x%08x\r\n", rosvInfo.wProductType);
	StringCchCatW(pwszData, stDataSize / sizeof(WCHAR), pwszTemp);
	StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszData);

	//firmware
	FIRMWARE_TYPE ftType = {0};
#ifndef WINDOWS7BUILD
	bRes = GetFirmwareType(&ftType);
	if (bRes)
	{
		switch (ftType)
		{
		case FirmwareTypeBios:
			{
				StringCchPrintfW(pwszTemp, stTempWchars, L"\tType: BIOS\r\n");
				break;
			}
		case FirmwareTypeUefi:
			{
				StringCchPrintfW(pwszTemp, stTempWchars, L"\tType: UEFI\r\n");
				break;
			}
		default:
			{
				StringCchPrintfW(pwszTemp, stTempWchars, L"\tType: Unknown\r\n");
			}
		}
		pwszData[0] = L'\0';
		StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), L"Firmware:\r\n");
		StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszTemp);
	}
#endif

	SYSTEM_TIMEOFDAY_INFORMATION systemTimeOfDayInfo = {0};
	NTSTATUS status;

	status = NtQuerySystemInformation(
		SystemTimeOfDayInformation,
		&systemTimeOfDayInfo,
		sizeof(SYSTEM_TIMEOFDAY_INFORMATION),
		NULL);
	if (STATUS_SUCCESS == status)
	{
		StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), L"Times:\r\n");

		SYSTEMTIME stBootTime = {0};
		PWSTR pwszBootTimestamp;
		FileTimeToSystemTime((FILETIME*)&(systemTimeOfDayInfo.BootTime.QuadPart), &stBootTime);
		pwszBootTimestamp = SystemTimeToISO8601(stBootTime);

		StringCchPrintfW(
			pwszTemp,
			stTempWchars,
			L"\tBoot: %s",
			pwszBootTimestamp);
		StringCchCatW(pwszHNMBuf, stHNMBufSize / sizeof(WCHAR), pwszTemp);
		LocalFree(pwszBootTimestamp);
	}

	LocalFree(pwszData);
	LocalFree(pwszTemp);
	return TRUE;
}


PWSTR HNM_Output(void)
{
	wprintf(L"Getting OS Data\r\n");
	stHNMBufSize = SIZE_1MB;

	pwszHNMBuf = LocalAlloc(LPTR, stHNMBufSize);
	CRASHIFNULLALLOC(pwszHNMBuf);

	AddCheckHeader(pwszHNMBuf, stHNMBufSize, L"OS Data", FALSE);

	HNMMain();
	ShrinkWcharBuffer(&pwszHNMBuf);
	return pwszHNMBuf;
}
