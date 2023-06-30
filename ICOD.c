#include "VSTriage.h"

PWSTR pwszICODBuf = NULL;
size_t stICODBufSize;
#define DNS_QUERY_CACHE_NO_FLAGS_MATCH      0x00008000

#define DNS_LIMIT_VISTA 300
#define DNS_LIMIT_7SP1 1500
#define DNS_LIMIT_81 15000

DWORD ICODGetMaxEntriesLimit(void)
{
	DWORD dwLimit = DNS_LIMIT_VISTA;
	if (IsWindows7SP1OrGreater())
	{
		dwLimit = DNS_LIMIT_7SP1;
		//REPORTERROR(L"All ok. 7", 7);
	}
	if (IsWindows8Point1OrGreater())
	{
		dwLimit = DNS_LIMIT_81;
		//REPORTERROR(L"All ok. 8.1", 8);
	}
	if (IsWindows10OrGreater())
	{
		dwLimit = DNS_LIMIT_81;
		//REPORTERROR(L"All ok. 10", 10);
	}
	return dwLimit;
}


BOOL ICODRecordData(PDNS_RECORD DnsRecord, PWSTR RecordDataString, DWORD DataChCount)
{
	WCHAR pwszIPAddress[IP6_ADDRESS_STRING_BUFFER_LENGTH];

	switch (DnsRecord->wType)
	{
	case DNS_TYPE_A:
		RtlIpv4AddressToStringW((PIN_ADDR)&DnsRecord->Data.A.IpAddress, pwszIPAddress);
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			pwszIPAddress);
		break;

	case DNS_TYPE_NS:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			DnsRecord->Data.NS.pNameHost);
		break;

	case DNS_TYPE_CNAME:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			DnsRecord->Data.CNAME.pNameHost);
		break;

	case DNS_TYPE_SOA:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"DefaultTtl: %i, Expire: %i, Refresh: %i, Retry: %i, SerialNo: %i, Administrator: %s, NamePrimaryServer: %s",
			DnsRecord->Data.SOA.dwDefaultTtl,
			DnsRecord->Data.SOA.dwExpire,
			DnsRecord->Data.SOA.dwRefresh,
			DnsRecord->Data.SOA.dwRetry,
			DnsRecord->Data.SOA.dwSerialNo,
			DnsRecord->Data.SOA.pNameAdministrator,
			DnsRecord->Data.SOA.pNamePrimaryServer);
		break;

	case DNS_TYPE_PTR:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			DnsRecord->Data.PTR.pNameHost);
		break;

	case DNS_TYPE_MX:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"Preference: %i, NameExchange: %s",
			DnsRecord->Data.MX.wPreference,
			DnsRecord->Data.MX.pNameExchange);
		break;

	case DNS_TYPE_AAAA:
		RtlIpv6AddressToStringW((PIN6_ADDR)&DnsRecord->Data.AAAA.Ip6Address, pwszIPAddress);
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			pwszIPAddress);
		break;

	case DNS_TYPE_SRV:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"Name: %s, Priority: %i, Weight: %i, Port: %i",
			DnsRecord->Data.SRV.pNameTarget,
			DnsRecord->Data.SRV.wPriority,
			DnsRecord->Data.SRV.wWeight,
			DnsRecord->Data.SRV.wPort);
		break;

	default:
		StringCchPrintfW(
			RecordDataString,
			DataChCount,
			L"%s",
			L"???");
	}

	return TRUE;
}


BOOL
GetDnsCachedData(
	__in IN LPWSTR Name,
	__in IN WORD Type
)
{
	PDNS_RECORD DnsRecord;
	PDNS_RECORD DnsRecordHead = NULL;
	DNS_STATUS DnsStatus;

	DnsStatus = DnsQuery_W(
		Name,
		Type,
		DNS_QUERY_CACHE_ONLY | DNS_QUERY_CACHE_NO_FLAGS_MATCH | DNS_QUERY_NO_HOSTS_FILE,
		// | DNS_QUERY_NO_HOSTS_FILE, // nicer, but ipconfig does not use it.
		NULL,
		&DnsRecordHead,
		NULL);
	
	DnsRecord = DnsRecordHead;

	if (DnsStatus != NO_ERROR)
	{
		switch (DnsStatus)
		{
		case DNS_INFO_NO_RECORDS: //quite normal, return, no records anyway
			return TRUE;
		//break;
		case DNS_ERROR_RCODE_SERVER_FAILURE:
			wprintf(L"ERROR: Server failure. %s\r\n", Name);
			break;
		case DNS_ERROR_RCODE_NAME_ERROR:
			wprintf(L"ERROR: Name Error. %s\r\n", Name);
			break;
		case ERROR_TIMEOUT:
			wprintf(L"ERROR: Timeout. %s\r\n", Name);
			break;
		case DNS_ERROR_RECORD_DOES_NOT_EXIST:
			//ignore
			break;
		default:
			wprintf(L"ERROR: Unknown Error. %s\r\n", Name);
		}
		DnsRecordListFree(DnsRecordHead, TRUE);
		return FALSE;
	}

	PWSTR pwszAllRecordsWorkBuf;
	DWORD dwAllRecordsWorkBufChCount;
	dwAllRecordsWorkBufChCount = SIZE_1KB;
	pwszAllRecordsWorkBuf = (PWSTR)LocalAlloc(LPTR, dwAllRecordsWorkBufChCount * sizeof(WCHAR));
	CRASHIFNULLALLOC(pwszAllRecordsWorkBuf);

	PWSTR pwszAllRecordsDataBuf;
	DWORD dwAllRecordsDataBufChCount;
	dwAllRecordsDataBufChCount = SIZE_1MB;
	pwszAllRecordsDataBuf = (PWSTR)LocalAlloc(LPTR, dwAllRecordsDataBufChCount * sizeof(WCHAR));
	CRASHIFNULLALLOC(pwszAllRecordsDataBuf);

	StringCchPrintfW(pwszAllRecordsWorkBuf, dwAllRecordsWorkBufChCount, L"Name: %ls\r\n", Name);
	StringCchCatW(pwszAllRecordsDataBuf, dwAllRecordsDataBufChCount, pwszAllRecordsWorkBuf);

	while (NULL != DnsRecord)
	{
		PWSTR pwszDnsRecordTempBuf;
		DWORD dwDnsRecordBufChCount = SIZE_1KB;
		pwszDnsRecordTempBuf = (PWSTR)LocalAlloc(LPTR, dwDnsRecordBufChCount * sizeof(WCHAR));
		CRASHIFNULLALLOC(pwszDnsRecordTempBuf);

		switch (DnsRecord->wType)
		{
		case DNS_TYPE_A:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"A");
			break;
		case DNS_TYPE_NS:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"NS");
			break;
		case DNS_TYPE_CNAME:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"CNAME");
			break;
		case DNS_TYPE_SOA:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"SOA");
			break;
		case DNS_TYPE_PTR:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"PTR");
			break;
		case DNS_TYPE_MX:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"MX");
			break;
		case DNS_TYPE_AAAA:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"AAAA");
			break;
		case DNS_TYPE_SRV:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"SRV");
			break;
		default:
			StringCchPrintfW(pwszDnsRecordTempBuf, dwDnsRecordBufChCount, L"%s", L"?");
		}

		StringCchPrintfW(
			pwszAllRecordsWorkBuf,
			dwAllRecordsWorkBufChCount,
			L"\tType: %i (%s)\r\n",
			DnsRecord->wType,
			pwszDnsRecordTempBuf);
		StringCchCatW(pwszAllRecordsDataBuf, dwAllRecordsDataBufChCount, pwszAllRecordsWorkBuf);

		StringCchPrintfW(
			pwszAllRecordsWorkBuf,
			dwAllRecordsWorkBufChCount,
			L"\t\tTTL: %i\r\n",
			DnsRecord->dwTtl);
		StringCchCatW(pwszAllRecordsDataBuf, dwAllRecordsDataBufChCount, pwszAllRecordsWorkBuf);


		StringCchPrintfW(
			pwszAllRecordsWorkBuf,
			dwAllRecordsWorkBufChCount,
			L"\t\tFlags: 0x%08x\r\n",
			DnsRecord->Flags.DW);
		StringCchCatW(pwszAllRecordsDataBuf, dwAllRecordsDataBufChCount, pwszAllRecordsWorkBuf);

		ICODRecordData(DnsRecord, pwszDnsRecordTempBuf, dwDnsRecordBufChCount);

		StringCchPrintfW(
			pwszAllRecordsWorkBuf,
			dwAllRecordsWorkBufChCount,
			L"\t\tData: %s\r\n",
			pwszDnsRecordTempBuf);
		StringCchCatW(pwszAllRecordsDataBuf, dwAllRecordsDataBufChCount, pwszAllRecordsWorkBuf);

		LocalFree(pwszDnsRecordTempBuf);
		DnsRecord = DnsRecord->pNext;
	}
	DnsRecordListFree(DnsRecordHead, TRUE);

	StringCchCatW(pwszICODBuf, stICODBufSize, pwszAllRecordsDataBuf);

	LocalFree(pwszAllRecordsDataBuf);
	LocalFree(pwszAllRecordsWorkBuf);
	return TRUE;
}


BOOL ICODMain(void)
{
	PDNS_CACHE_TABLE pDNSCacheTable = NULL;
	PDNS_CACHE_TABLE pTempDNSCacheTable;
	DWORD dwRecordCount = 0;

	if (!DnsGetCacheDataTable(&pDNSCacheTable)) //get error + display
	{
		//wprintf(L"\tListing DNS Cache failed.\r\n");
		REPORTERROR(L"Listing DNS Cache failed", GetLastError());
		return FALSE;
	}


	pTempDNSCacheTable = pDNSCacheTable;

	while (pTempDNSCacheTable)
	{
		PDNS_CACHE_TABLE pNext = pTempDNSCacheTable->pNext;

		if (pTempDNSCacheTable->Type1 != DNS_TYPE_ZERO)
		{
			GetDnsCachedData(
				pTempDNSCacheTable->Name,
				pTempDNSCacheTable->Type1);
		}

		if (pTempDNSCacheTable->Type2 != DNS_TYPE_ZERO)
		{
			GetDnsCachedData(
				pTempDNSCacheTable->Name,
				pTempDNSCacheTable->Type2);
		}

		if (pTempDNSCacheTable->Type3 != DNS_TYPE_ZERO)
		{
			GetDnsCachedData(
				pTempDNSCacheTable->Name,
				pTempDNSCacheTable->Type3);
		}

		DnsFree(pTempDNSCacheTable->Name, DnsFreeFlat);
		DnsFree(pTempDNSCacheTable, DnsFreeFlat);

		ResizeWcharBufIfNeeded(&pwszICODBuf, &stICODBufSize);

		dwRecordCount++;

		pTempDNSCacheTable = pNext;
	}

	//REPORTERROR(L" ---> MAX: ", ICODGetMaxEntriesLimit());
	//REPORTERROR(L" ---> Current: ", dwRecordCount);

	if (ICODGetMaxEntriesLimit() == dwRecordCount)
	{
		StringCchCatW(
			pwszICODBuf,
			stICODBufSize / sizeof(WCHAR),
			L"(DNS Cache content may be incomplete due to API limits.)\r\n");
		wprintf(L" (may be incomplete)");
	}
	return TRUE;
}


PWSTR ICOD_Output(void)
{
	wprintf(L"Listing DNS Cache");
	stICODBufSize = SIZE_16MB;

	ALLOCORCRASH(pwszICODBuf, stICODBufSize);

	AddCheckHeader(pwszICODBuf, stICODBufSize, L"DNS Cache", TRUE);

	ICODMain();
	ShrinkWcharBuffer(&pwszICODBuf);
	wprintf(L"\r\n");
	return pwszICODBuf;
}
