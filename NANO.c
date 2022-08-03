#include "VSTriage.h"

PWSTR pwszNANOBuf = NULL;
size_t stNANOBufSize;

PWSTR pwszStates[13] = {
	L"??",
	L"CLOSED",
	L"LISTEN",
	L"SYN-SENT",
	L"SYN-RECEIVED",
	L"ESTABLISHED",
	L"FIN-WAIT-1",
	L"FIN-WAIT-2",
	L"CLOSE-WAIT",
	L"CLOSING",
	L"LAST-ACK",
	L"LAST-ACK",
	L"DELETE-TCB"
};


VOID DisplayTcpv4Table(void)
{
	DWORD dwStatus;
	DWORD dwTableSize;
	PMIB_TCPTABLE_OWNER_MODULE ptomTable;

	// loop asking for size
	dwTableSize = 0;
	ptomTable = NULL;
	dwStatus = ERROR_INSUFFICIENT_BUFFER;
	while (ERROR_INSUFFICIENT_BUFFER == dwStatus)
	{
		if (ptomTable)
		{
			LocalFree(ptomTable);
		}
		ptomTable = (PMIB_TCPTABLE_OWNER_MODULE)LocalAlloc(LPTR, dwTableSize);
		CRASHIFNULLALLOC(ptomTable);
		dwStatus = GetExtendedTcpTable(ptomTable, &dwTableSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
	}

	if (NO_ERROR != dwStatus)
	{
		LocalFree(ptomTable);
		REPORTERROR(L"", dwStatus);
		return;
	}

	for (DWORD i = 0; i < ptomTable->dwNumEntries; i++)
	{
		WCHAR wszLine[SIZE_1KB] = {0};
		WCHAR wszPart[SIZE_1KB] = {0};

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"TCP\t");

		RtlIpv4AddressToStringW((PIN_ADDR)&ptomTable->table[i].dwLocalAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwLocalPort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		RtlIpv4AddressToStringW((PIN_ADDR)&ptomTable->table[i].dwRemoteAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwRemotePort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s\t", pwszStates[ptomTable->table[i].dwState]);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%i\t", ptomTable->table[i].dwOwningPid);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		if (0 != ptomTable->table[i].liCreateTimestamp.QuadPart)
		{
			PWSTR pwszTimestamp;
			SYSTEMTIME stStamp;
			FILETIME ftStamp;
			ftStamp.dwLowDateTime = ptomTable->table[i].liCreateTimestamp.LowPart;
			ftStamp.dwHighDateTime = ptomTable->table[i].liCreateTimestamp.HighPart;
			FileTimeToSystemTime(&ftStamp, &stStamp);
			pwszTimestamp = SystemTimeToISO8601(stStamp);
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", pwszTimestamp);
			LocalFree(pwszTimestamp);
		}
		else
		{
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", L"Unknown");
		}

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), wszLine);
		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), L"\r\n");
	}
	LocalFree(ptomTable);
}

VOID DisplayTcpv6Table(void)
{
	DWORD dwStatus;
	DWORD dwTableSize;
	PMIB_TCP6TABLE_OWNER_MODULE ptomTable;

	// loop asking for size
	dwTableSize = 0;
	ptomTable = NULL;
	dwStatus = ERROR_INSUFFICIENT_BUFFER;
	while (ERROR_INSUFFICIENT_BUFFER == dwStatus)
	{
		if (ptomTable)
		{
			LocalFree(ptomTable);
		}
		ptomTable = (PMIB_TCP6TABLE_OWNER_MODULE)LocalAlloc(LPTR, dwTableSize);
		CRASHIFNULLALLOC(ptomTable);

		dwStatus = GetExtendedTcpTable(ptomTable, &dwTableSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
	}

	if (NO_ERROR != dwStatus)
	{
		LocalFree(ptomTable);
		REPORTERROR(L"", dwStatus);
		return;
	}
	for (DWORD i = 0; i < ptomTable->dwNumEntries; i++)
	{
		WCHAR wszLine[SIZE_1KB] = {0};
		WCHAR wszPart[SIZE_1KB] = {0};

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"TCP\t");

		RtlIpv6AddressToStringW((PIN6_ADDR)&ptomTable->table[i].ucLocalAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"[");
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"]");
		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwLocalPort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		RtlIpv6AddressToStringW((PIN6_ADDR)&ptomTable->table[i].ucRemoteAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"[");
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"]");
		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwRemotePort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s\t", pwszStates[ptomTable->table[i].dwState]);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%i\t", ptomTable->table[i].dwOwningPid);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		if (0 != ptomTable->table[i].liCreateTimestamp.QuadPart)
		{
			PWSTR pwszTimestamp;
			SYSTEMTIME stStamp;
			FILETIME ftStamp;
			ftStamp.dwLowDateTime = ptomTable->table[i].liCreateTimestamp.LowPart;
			ftStamp.dwHighDateTime = ptomTable->table[i].liCreateTimestamp.HighPart;
			FileTimeToSystemTime(&ftStamp, &stStamp);
			pwszTimestamp = SystemTimeToISO8601(stStamp);
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", pwszTimestamp);
			LocalFree(pwszTimestamp);
		}
		else
		{
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", L"Unknown");
		}

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), wszLine);
		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), L"\r\n");
	}
	LocalFree(ptomTable);
}

VOID DisplayUdpv4Table(void)
{
	DWORD dwStatus;
	DWORD dwTableSize;
	PMIB_UDPTABLE_OWNER_MODULE ptomTable;

	// loop asking for size
	dwTableSize = 0;
	ptomTable = NULL;
	dwStatus = ERROR_INSUFFICIENT_BUFFER;
	while (ERROR_INSUFFICIENT_BUFFER == dwStatus)
	{
		if (ptomTable)
		{
			LocalFree(ptomTable);
		}
		ptomTable = (PMIB_UDPTABLE_OWNER_MODULE)LocalAlloc(LPTR, dwTableSize);
		CRASHIFNULLALLOC(ptomTable);

		dwStatus = GetExtendedUdpTable(ptomTable, &dwTableSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
	}

	if (NO_ERROR != dwStatus)
	{
		LocalFree(ptomTable);
		REPORTERROR(L"", dwStatus);
		return;
	}

	for (DWORD i = 0; i < ptomTable->dwNumEntries; i++)
	{
		WCHAR wszLine[SIZE_1KB] = {0};
		WCHAR wszPart[SIZE_1KB] = {0};

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"UDP\t");

		RtlIpv4AddressToStringW((PIN_ADDR)&ptomTable->table[i].dwLocalAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwLocalPort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"*.*\t");

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%i\t", ptomTable->table[i].dwOwningPid);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		if (0 != ptomTable->table[i].liCreateTimestamp.QuadPart)
		{
			PWSTR pwszTimestamp;
			SYSTEMTIME stStamp;
			FILETIME ftStamp;
			ftStamp.dwLowDateTime = ptomTable->table[i].liCreateTimestamp.LowPart;
			ftStamp.dwHighDateTime = ptomTable->table[i].liCreateTimestamp.HighPart;
			FileTimeToSystemTime(&ftStamp, &stStamp);
			pwszTimestamp = SystemTimeToISO8601(stStamp);
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", pwszTimestamp);
			LocalFree(pwszTimestamp);
		}
		else
		{
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", L"Unknown");
		}

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), wszLine);
		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), L"\r\n");
	}
	LocalFree(ptomTable);
}

VOID DisplayUdpv6Table(void)
{
	DWORD dwStatus;
	DWORD dwTableSize;
	PMIB_UDP6TABLE_OWNER_MODULE ptomTable;

	// loop asking for size
	dwTableSize = 0;
	ptomTable = NULL;
	dwStatus = ERROR_INSUFFICIENT_BUFFER;
	while (ERROR_INSUFFICIENT_BUFFER == dwStatus)
	{
		if (ptomTable)
		{
			LocalFree(ptomTable);
		}
		ptomTable = (PMIB_UDP6TABLE_OWNER_MODULE)LocalAlloc(LPTR, dwTableSize);
		CRASHIFNULLALLOC(ptomTable);

		dwStatus = GetExtendedUdpTable(ptomTable, &dwTableSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
	}

	if (NO_ERROR != dwStatus)
	{
		LocalFree(ptomTable);
		REPORTERROR(L"", dwStatus);
		return;
	}

	for (DWORD i = 0; i < ptomTable->dwNumEntries; i++)
	{
		WCHAR wszLine[SIZE_1KB] = {0};
		WCHAR wszPart[SIZE_1KB] = {0};

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"UDP\t");

		RtlIpv6AddressToStringW((PIN6_ADDR)&ptomTable->table[i].ucLocalAddr, wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"[");
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"]");

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L":%i\t", ntohs((u_short)ptomTable->table[i].dwLocalPort));
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), L"*.*\t");

		StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%i\t", ptomTable->table[i].dwOwningPid);
		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);

		if (0 != ptomTable->table[i].liCreateTimestamp.QuadPart)
		{
			PWSTR pwszTimestamp;
			SYSTEMTIME stStamp;
			FILETIME ftStamp;
			ftStamp.dwLowDateTime = ptomTable->table[i].liCreateTimestamp.LowPart;
			ftStamp.dwHighDateTime = ptomTable->table[i].liCreateTimestamp.HighPart;
			FileTimeToSystemTime(&ftStamp, &stStamp);
			pwszTimestamp = SystemTimeToISO8601(stStamp);
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", pwszTimestamp);
			LocalFree(pwszTimestamp);
		}
		else
		{
			StringCchPrintfW(wszPart, ARRAYSIZE(wszPart), L"%s", L"Unknown");
		}

		StringCchCatW(wszLine, ARRAYSIZE(wszLine), wszPart);
		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), wszLine);
		StringCchCatW(pwszNANOBuf, stNANOBufSize / sizeof(WCHAR), L"\r\n");
	}
	LocalFree(ptomTable);
}


BOOL NANOMain(void)
{
	DisplayTcpv4Table();
	ResizeWcharBufIfNeeded(&pwszNANOBuf, &stNANOBufSize);
	DisplayTcpv6Table();
	ResizeWcharBufIfNeeded(&pwszNANOBuf, &stNANOBufSize);
	DisplayUdpv4Table();
	ResizeWcharBufIfNeeded(&pwszNANOBuf, &stNANOBufSize);
	DisplayUdpv6Table();
	return TRUE; 
}


PWSTR NANO_Output(void)
{
	wprintf(L"Listing TCP/IP Connections\r\n");
	stNANOBufSize = SIZE_1MB;

	pwszNANOBuf = LocalAlloc(LPTR, stNANOBufSize);
	CRASHIFNULLALLOC(pwszNANOBuf);

	AddCheckHeader(pwszNANOBuf, stNANOBufSize, L"TCP/IP Connections", TRUE);

	NANOMain();

	ShrinkWcharBuffer(&pwszNANOBuf);
	return pwszNANOBuf;
}
