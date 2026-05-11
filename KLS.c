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
		
		WCHAR wszLine[SIZE_1KB] = { 0 };
		WCHAR wszPart[SIZE_1KB] = { 0 };
		
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

			//ARM64 fix - %wZ failed, so copy the data to local buffers and print with %s
			WCHAR wszLogonDomain[SIZE_1KB] = { 0 };
			WCHAR wszUserName[SIZE_1KB] = { 0 };
			memcpy_s(wszLogonDomain, sizeof(wszLogonDomain), pslsaData->LogonDomain.Buffer, pslsaData->LogonDomain.Length);
			memcpy_s(wszUserName, sizeof(wszUserName), pslsaData->UserName.Buffer, pslsaData->UserName.Length);


			PWSTR pwszSid = NULL;
			ConvertSidToStringSidW(pslsaData->Sid, &pwszSid);

			StringCchPrintfW(
				wszPart,
				ARRAYSIZE(wszPart),
				L"\tUser: %s\\%s (%s)\r\n",
				wszLogonDomain,
				wszUserName,
				pwszSid);

			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			if (NULL != pwszSid)
			{
				LocalFree(pwszSid);
			}

			WCHAR wszAuthPackage[SIZE_1KB] = { 0 };
			memcpy_s(wszAuthPackage, sizeof(wszAuthPackage), pslsaData->AuthenticationPackage.Buffer, pslsaData->AuthenticationPackage.Length);

			StringCchPrintfW(
				wszPart,
				ARRAYSIZE(wszPart),
				L"\tAuthentication: %s:%s\r\n",
				wszAuthPackage,
				pwszLogonTypes[pslsaData->LogonType]);
			StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);


			WCHAR wszLsaData[SIZE_1KB] = { 0 };
			if (0 != pslsaData->LogonServer.Length)
			{
				memcpy_s(wszLsaData, sizeof(wszLsaData), pslsaData->LogonServer.Buffer, pslsaData->LogonServer.Length);
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tLogonServer: %s\r\n", wszLsaData);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			}


			if (0 != pslsaData->DnsDomainName.Length)
			{
				ZeroMemory(wszLsaData, sizeof(wszLsaData));
				memcpy_s(wszLsaData, sizeof(wszLsaData), pslsaData->DnsDomainName.Buffer, pslsaData->DnsDomainName.Length);
				StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tDnsDomainName: %s\r\n", wszLsaData);
				StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
			}


			if (0 != pslsaData->Upn.Length)
			{
				if (0 != wcslen(pslsaData->Upn.Buffer)) //it may happen!
				{
					ZeroMemory(wszLsaData, sizeof(wszLsaData));
					memcpy_s(wszLsaData, sizeof(wszLsaData), pslsaData->Upn.Buffer, pslsaData->Upn.Length);
					StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"\tUpn: %s\r\n", wszLsaData);
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
		//wprintf(L"%s", wszLine);
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
