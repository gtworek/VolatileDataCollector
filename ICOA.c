#include "VSTriage.h"

PWSTR pwszICOABuf = NULL;
size_t stICOABufSize;


VOID
ICOAGetInterfaceInfo(
	PIP_ADAPTER_ADDRESSES pipInterface
)
{
	WCHAR AddressBuffer[INET6_ADDRSTRLEN];
	PWSTR pwszTempString;
	const size_t stcTempStringCchLen = SIZE_16MB;
	pwszTempString = LocalAlloc(LPTR, stcTempStringCchLen * sizeof(WCHAR)); //size in wchars
	CRASHIFNULLALLOC(pwszTempString);

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"IfIndex [0x%x]\r\n", pipInterface->IfIndex);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);


	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tName: %hs\r\n", pipInterface->AdapterName);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tFriendly Name: %s\r\n", pipInterface->FriendlyName);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tDescription: %s\r\n", pipInterface->Description);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tOperStatus: ");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	switch (pipInterface->OperStatus)
	{
	case IfOperStatusUp:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"Up");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusDown:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"Down");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusTesting:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"Testing");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusUnknown:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"Unknown");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusDormant:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"Dormant");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusNotPresent:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"NotPresent");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	case IfOperStatusLowerLayerDown:
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"LayerDown");
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		break;
	}
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	AddressBuffer[0] = L'\0';
	if (pipInterface->PhysicalAddressLength > 0 && pipInterface->PhysicalAddressLength * 3 <= INET6_ADDRSTRLEN)
	{
		size_t i;
		for (i = 0; i < pipInterface->PhysicalAddressLength; i++)
		{
			StringCchPrintfW(
				&AddressBuffer[i * 3],
				RTL_NUMBER_OF(AddressBuffer) - (sizeof(AddressBuffer[0]) * i * 3),
				L"%02X-",
				pipInterface->PhysicalAddress[i]);
		}
		AddressBuffer[i * 3 - 1] = L'\0';
	}

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tPhysical Address: %s\r\n", AddressBuffer);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tMTU: %i\r\n", pipInterface->Mtu);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(
		pwszTempString,
		stcTempStringCchLen,
		L"\tDHCPv4: %s\r\n",
		(BOOL)(pipInterface->Dhcpv4Enabled) ? L"TRUE" : L"FALSE");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(
		pwszTempString,
		stcTempStringCchLen,
		L"\tNetBios over TCP/IP: %s\r\n",
		(BOOL)(pipInterface->NetbiosOverTcpipEnabled) ? L"TRUE" : L"FALSE");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(
		pwszTempString,
		stcTempStringCchLen,
		L"\tRegisterAdapterSuffix: %s\r\n",
		(BOOL)(pipInterface->RegisterAdapterSuffix) ? L"TRUE" : L"FALSE");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tIANA ifType: %i\r\n", pipInterface->IfType);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(
		pwszTempString,
		stcTempStringCchLen,
		L"\tSpeed Tx/Rx [bps]: %lli/%lli\r\n",
		pipInterface->TransmitLinkSpeed,
		pipInterface->ReceiveLinkSpeed);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tDns Suffix: %s\r\n", pipInterface->DnsSuffix);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	PIP_ADAPTER_DNS_SUFFIX pipaDnsSuffix;
	pipaDnsSuffix = pipInterface->FirstDnsSuffix;
	while (NULL != pipaDnsSuffix)
	{
		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\t%ls\r\n", pipaDnsSuffix->String);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
		pipaDnsSuffix = pipaDnsSuffix->Next;
	}

	PSOCKADDR_IN psin;
	PSOCKADDR_IN6 psin6;

	psin = (PSOCKADDR_IN)pipInterface->Dhcpv4Server.lpSockaddr;
	AddressBuffer[0] = L'\0';
	if (psin)
	{
		InetNtopW(AF_INET, &psin->sin_addr, AddressBuffer, ARRAYSIZE(AddressBuffer));
	}
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tDHCPv4 Server: %s\r\n", AddressBuffer);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	psin6 = (PSOCKADDR_IN6)pipInterface->Dhcpv6Server.lpSockaddr;
	AddressBuffer[0] = L'\0';
	if (psin6)
	{
		InetNtopW(AF_INET6, &psin6->sin6_addr, AddressBuffer, ARRAYSIZE(AddressBuffer));
	}
	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tDHCPv6 Server: %s\r\n", AddressBuffer);
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);


	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tUnicast:\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);
	PIP_ADAPTER_UNICAST_ADDRESS pipauAddress;
	pipauAddress = pipInterface->FirstUnicastAddress;
	while (NULL != pipauAddress)
	{
		switch (pipauAddress->Address.lpSockaddr->sa_family)
		{
		case AF_INET:
			psin = (PSOCKADDR_IN)pipauAddress->Address.lpSockaddr;
			InetNtopW(
				pipauAddress->Address.lpSockaddr->sa_family,
				&psin->sin_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		case AF_INET6:
			psin6 = (PSOCKADDR_IN6)pipauAddress->Address.lpSockaddr;
			InetNtopW(
				pipauAddress->Address.lpSockaddr->sa_family,
				&psin6->sin6_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		default:
			AddressBuffer[0] = L'\0';
		}

		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\tAddress: %s\r\n", AddressBuffer);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		StringCchPrintfW(
			pwszTempString,
			stcTempStringCchLen,
			L"\t\t\tValidLifetime [s]: %i\r\n",
			pipauAddress->ValidLifetime);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		StringCchPrintfW(
			pwszTempString,
			stcTempStringCchLen,
			L"\t\t\tPreferredLifetime [s]: %i\r\n",
			pipauAddress->PreferredLifetime);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		StringCchPrintfW(
			pwszTempString,
			stcTempStringCchLen,
			L"\t\t\tLeaseLifetime [s]: %i\r\n",
			pipauAddress->LeaseLifetime);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		StringCchPrintfW(
			pwszTempString,
			stcTempStringCchLen,
			L"\t\t\tOnLinkPrefixLength: %i\r\n",
			pipauAddress->OnLinkPrefixLength);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		pipauAddress = pipauAddress->Next;
	}

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tGateway:\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	PIP_ADAPTER_GATEWAY_ADDRESS pipagAddress;
	pipagAddress = pipInterface->FirstGatewayAddress;
	while (NULL != pipagAddress)
	{
		switch (pipagAddress->Address.lpSockaddr->sa_family)
		{
		case AF_INET:
			psin = (PSOCKADDR_IN)pipagAddress->Address.lpSockaddr;
			InetNtopW(
				pipagAddress->Address.lpSockaddr->sa_family,
				&psin->sin_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		case AF_INET6:
			psin6 = (PSOCKADDR_IN6)pipagAddress->Address.lpSockaddr;
			InetNtopW(
				pipagAddress->Address.lpSockaddr->sa_family,
				&psin6->sin6_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		default:
			AddressBuffer[0] = L'\0';
		}

		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\tAddress: %s\r\n", AddressBuffer);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		pipagAddress = pipagAddress->Next;
	}

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tDNS Server:\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	PIP_ADAPTER_DNS_SERVER_ADDRESS pipaDnsServerAddress;
	pipaDnsServerAddress = pipInterface->FirstDnsServerAddress;
	while (NULL != pipaDnsServerAddress)
	{
		switch (pipaDnsServerAddress->Address.lpSockaddr->sa_family)
		{
		case AF_INET:
			psin = (PSOCKADDR_IN)pipaDnsServerAddress->Address.lpSockaddr;
			InetNtopW(
				pipaDnsServerAddress->Address.lpSockaddr->sa_family,
				&psin->sin_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		case AF_INET6:
			psin6 = (PSOCKADDR_IN6)pipaDnsServerAddress->Address.lpSockaddr;
			InetNtopW(
				pipaDnsServerAddress->Address.lpSockaddr->sa_family,
				&psin6->sin6_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		default:
			AddressBuffer[0] = L'\0';
		}

		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\tAddress: %s\r\n", AddressBuffer);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		pipaDnsServerAddress = pipaDnsServerAddress->Next;
	}

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tAnycast:\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	PIP_ADAPTER_ANYCAST_ADDRESS pipaAnycastAddress;
	pipaAnycastAddress = pipInterface->FirstAnycastAddress;
	while (NULL != pipaAnycastAddress)
	{
		switch (pipaAnycastAddress->Address.lpSockaddr->sa_family)
		{
		case AF_INET:
			psin = (PSOCKADDR_IN)pipaAnycastAddress->Address.lpSockaddr;
			InetNtopW(
				pipaAnycastAddress->Address.lpSockaddr->sa_family,
				&psin->sin_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		case AF_INET6:
			psin6 = (PSOCKADDR_IN6)pipaAnycastAddress->Address.lpSockaddr;
			InetNtopW(
				pipaAnycastAddress->Address.lpSockaddr->sa_family,
				&psin6->sin6_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		default:
			AddressBuffer[0] = L'\0';
		}

		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\tAddress: %s\r\n", AddressBuffer);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		pipaAnycastAddress = pipaAnycastAddress->Next;
	}

	StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\tMulticast:\r\n");
	StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

	PIP_ADAPTER_MULTICAST_ADDRESS pipaMulticastAddress;
	pipaMulticastAddress = pipInterface->FirstMulticastAddress;
	while (NULL != pipaMulticastAddress)
	{
		switch (pipaMulticastAddress->Address.lpSockaddr->sa_family)
		{
		case AF_INET:
			psin = (PSOCKADDR_IN)pipaMulticastAddress->Address.lpSockaddr;
			InetNtopW(
				pipaMulticastAddress->Address.lpSockaddr->sa_family,
				&psin->sin_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		case AF_INET6:
			psin6 = (PSOCKADDR_IN6)pipaMulticastAddress->Address.lpSockaddr;
			InetNtopW(
				pipaMulticastAddress->Address.lpSockaddr->sa_family,
				&psin6->sin6_addr,
				AddressBuffer,
				ARRAYSIZE(AddressBuffer));
			break;
		default:
			AddressBuffer[0] = L'\0';
		}

		StringCchPrintfW(pwszTempString, stcTempStringCchLen, L"\t\tAddress: %s\r\n", AddressBuffer);
		StringCchCatW(pwszICOABuf, stICOABufSize / sizeof(WCHAR), pwszTempString);

		pipaMulticastAddress = pipaMulticastAddress->Next;
	}
	LocalFree(pwszTempString);
}

BOOL ICOAMain(void)
{
	ULONG ulBufferSize = 0;
	ULONG ulStatus;
	PIP_ADAPTER_ADDRESSES pBuf;
	const ULONG ulFlags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;

	ulStatus =
		GetAdaptersAddresses(
			AF_UNSPEC,
			ulFlags,
			NULL,
			NULL,
			&ulBufferSize);
	if (ERROR_BUFFER_OVERFLOW != ulStatus)
	{
		SetLastError(ulStatus);
		return FALSE;
	}

	pBuf = LocalAlloc(LPTR, ulBufferSize);
	if (!pBuf)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	ulStatus =
		GetAdaptersAddresses(
			AF_UNSPEC,
			ulFlags,
			NULL,
			pBuf,
			&ulBufferSize);
	if (ERROR_SUCCESS != ulStatus)
	{
		LocalFree(pBuf);
		return FALSE;
	}

	PIP_ADAPTER_ADDRESSES pipCurrent;
	pipCurrent = pBuf;
	while (NULL != pipCurrent)
	{
		ICOAGetInterfaceInfo(pipCurrent);
		pipCurrent = pipCurrent->Next;
	}


	LocalFree(pBuf);
	return TRUE;
}


PWSTR ICOA_Output(void)
{
	wprintf(L"Listing IP Config\r\n");
	stICOABufSize = SIZE_16MB;

	ALLOCORCRASH(pwszICOABuf, stICOABufSize);

	AddCheckHeader(pwszICOABuf, stICOABufSize, L"IP Config", FALSE);

	ICOAMain();
	ShrinkWcharBuffer(&pwszICOABuf);
	return pwszICOABuf;
}
