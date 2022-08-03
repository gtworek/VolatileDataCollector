#include "VSTriage.h"

PWSTR pwszArpaBuf = NULL;
size_t stArpaBufSize;


BOOL ARPAMain(void)
{
	PMIB_IPNET_TABLE2 pipTable;
	DWORD dwStatus;
	dwStatus = GetIpNetTable2(AF_UNSPEC, &pipTable);
	if (STATUS_SUCCESS != dwStatus)
	{
		wprintf(L"ERROR: GetIpNetTable2() returned 0x%08lx.\r\n", dwStatus);
		return (int)dwStatus;
	}

	ULONG i;
	unsigned int j;

	for (i = 0; i < pipTable->NumEntries; i++)
	{
		if (!pipTable->Table[i].PhysicalAddressLength) 
		{
			continue;
		}

		WCHAR wszAddr[INET6_ADDRSTRLEN] = L"???";
		WCHAR wszEntry[SIZE_1KB] = {0};
		WCHAR wszTemp[SIZE_1KB] = {0};
		StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"[0x%x]\t", pipTable->Table[i].InterfaceIndex);
		StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);

		for (j = 0; j < pipTable->Table[i].PhysicalAddressLength; j++)
		{
			if (j != pipTable->Table[i].PhysicalAddressLength - 1)
			{
				StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"%.2X-", (int)pipTable->Table[i].PhysicalAddress[j]);
				StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);
			}
			else
			{
				StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"%.2X", (int)pipTable->Table[i].PhysicalAddress[j]);
				StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);
			}
		}

		PVOID pvAddrAddr;
		switch (pipTable->Table[i].Address.si_family)
		{
		case AF_INET:
			pvAddrAddr = &pipTable->Table[i].Address.Ipv4.sin_addr;
			break;
		case AF_INET6:
			pvAddrAddr = &pipTable->Table[i].Address.Ipv6.sin6_addr;
			break;
		default:
			pvAddrAddr = NULL;
		}

		if (NULL != pvAddrAddr)
		{
			InetNtopW(pipTable->Table[i].Address.si_family, pvAddrAddr, wszAddr, ARRAYSIZE(wszAddr)); 
		}

		StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\t%s", wszAddr);
		StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);

		switch (pipTable->Table[i].State)
		{
		case NlnsUnreachable:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsUnreachable");
			break;
		case NlnsIncomplete:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsIncomplete");
			break;
		case NlnsProbe:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsProbe");
			break;
		case NlnsDelay:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsDelay");
			break;
		case NlnsStale:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsStale");
			break;
		case NlnsReachable:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsReachable");
			break;
		case NlnsPermanent:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsPermanent");
			break;
		case NlnsMaximum:
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tNlnsUnknown");
			break;
		}
		StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);

		if (pipTable->Table[i].IsRouter)
		{
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tIsRouter");
			StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);
		}
		if (pipTable->Table[i].IsUnreachable)
		{
			StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\tIsUnreachable");
			StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);
		}

		StringCchPrintfW(wszTemp, ARRAYSIZE(wszTemp), L"\r\n");
		StringCchCatW(wszEntry, ARRAYSIZE(wszEntry), wszTemp);

		StringCchCatW(pwszArpaBuf, stArpaBufSize / sizeof(WCHAR), wszEntry);
	} //for

	FreeMibTable(pipTable);
	pipTable = NULL;
	return TRUE;
}


PWSTR ARPA_Output(void)
{
	wprintf(L"Listing ARP Cache\r\n");
	stArpaBufSize = SIZE_16MB;

	ALLOCORCRASH(pwszArpaBuf, stArpaBufSize);

	AddCheckHeader(pwszArpaBuf, stArpaBufSize, L"ARP Cache", TRUE);

	ARPAMain();
	ShrinkWcharBuffer(&pwszArpaBuf);
	return pwszArpaBuf;
}
