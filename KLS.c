#include "VSTriage.h"
#include <ntlsa.h> //out??
#include <sddl.h>

PWSTR pwszKLSBuf = NULL;
size_t stKLSBufSize;

PWSTR pwszLogonTypes[14] = {
	L"UndefinedLogonType",
	L"???",
	L"Interactive",
	L"Network",
	L"Batch",
	L"Service",
	L"Proxy",
	L"Unlock",
	L"NetworkCleartext",
	L"NewCredentials",
	L"RemoteInteractive",
	L"CachedInteractive",
	L"CachedRemoteInteractive",
	L"CachedUnlock"
};

BOOL KLSMain(void)
{
	ULONG ulSessionCount;
	PLUID plLUID;
	BOOL bError = FALSE;
	NTSTATUS status;
	status = LsaEnumerateLogonSessions(&ulSessionCount, &plLUID);

	for (ULONG i = 0; i < ulSessionCount; i++)
	{
		WCHAR wszLine[SIZE_1KB] = {0};
		WCHAR wszPart[SIZE_1KB] = {0};
		PSECURITY_LOGON_SESSION_DATA pslsaData = NULL;
		status = LsaGetLogonSessionData(&plLUID[i], &pslsaData);
		if (STATUS_SUCCESS != status)
		{
			if (STATUS_ACCESS_DENIED != status) //dont report accessdenied. it happens on regular user.
			{
				REPORTERROR(L"LsaGetLogonSessionData() failed with status ", status);
			}
			bError = TRUE;
		}
		if (NULL != pslsaData)
		{
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"[0x%02x] ", i);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);


			StringCchPrintfW(
				wszPart,
				ARRAYSIZE(wszPart),
				L"\tLUID: %x:0x%x\r\n",
				pslsaData->LogonId.HighPart,
				pslsaData->LogonId.LowPart);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);


			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tSession: %i\r\n", pslsaData->Session);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);


			PWSTR pwszSid = NULL;
			ConvertSidToStringSidW(pslsaData->Sid, &pwszSid);
			StringCchPrintfW(
				wszPart,
				ARRAYSIZE(wszPart),
				L"\tUser: %wZ\\%wZ (%s)\r\n",
				pslsaData->LogonDomain,
				pslsaData->UserName,
				pwszSid);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			if (NULL != pwszSid)
			{
				LocalFree(pwszSid);
			}


			StringCchPrintfW(
				wszPart,
				ARRAYSIZE(wszPart),
				L"\tAuthentication: %wZ:%s\r\n",
				pslsaData->AuthenticationPackage,
				pwszLogonTypes[pslsaData->LogonType]);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);


			if (0 != pslsaData->LogonServer.Length)
			{
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tLogonServer: %wZ\r\n", pslsaData->LogonServer);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			}


			if (0 != pslsaData->DnsDomainName.Length)
			{
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tDnsDomainName: %wZ\r\n", pslsaData->DnsDomainName);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			}


			if (0 != pslsaData->Upn.Length)
			{
				if (0 != wcslen(pslsaData->Upn.Buffer)) //it may happen!
				{
					StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tUpn: %wZ\r\n", pslsaData->Upn);
					StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
				}
			}


			if (0 != pslsaData->LogonTime.QuadPart)
			{
				PWSTR pwszTimestamp;
				SYSTEMTIME stStamp;
				FILETIME ftStamp;
				ftStamp.dwLowDateTime = pslsaData->LogonTime.LowPart;
				ftStamp.dwHighDateTime = pslsaData->LogonTime.HighPart;
				FileTimeToSystemTime(&ftStamp, &stStamp);
				pwszTimestamp = SystemTimeToISO8601(stStamp);
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tLogonTime: %s\r\n", pwszTimestamp);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
				LocalFree(pwszTimestamp);
			}


			if (0 != pslsaData->PasswordLastSet.QuadPart)
			{
				PWSTR pwszTimestamp;
				SYSTEMTIME stStamp;
				FILETIME ftStamp;
				ftStamp.dwLowDateTime = pslsaData->PasswordLastSet.LowPart;
				ftStamp.dwHighDateTime = pslsaData->PasswordLastSet.HighPart;
				FileTimeToSystemTime(&ftStamp, &stStamp);
				pwszTimestamp = SystemTimeToISO8601(stStamp);
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tPasswordLastSet: %s\r\n", pwszTimestamp);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
				LocalFree(pwszTimestamp);
			}


			LsaFreeReturnBuffer(pslsaData);
		}
		StringCchCatW(pwszKLSBuf, stKLSBufSize / sizeof(WCHAR), wszLine);
	}

	LsaFreeReturnBuffer(plLUID); //ignore result
	if (bError)
	{
		StringCchCatW(
			pwszKLSBuf,
			stKLSBufSize / sizeof(WCHAR),
			L"(Results may be incomplete. Probably due to lack of privileges.)\r\n");
		wprintf(L" (some errors)");
	}
	return TRUE;
}


PWSTR KLS_Output(void)
{
	wprintf(L"Listing Logons");
	stKLSBufSize = SIZE_1MB;

	ALLOCORCRASH(pwszKLSBuf, stKLSBufSize);

	AddCheckHeader(pwszKLSBuf, stKLSBufSize, L"Logons", FALSE);

	KLSMain();
	ShrinkWcharBuffer(&pwszKLSBuf);
	wprintf(L"\r\n");
	return pwszKLSBuf;
}
