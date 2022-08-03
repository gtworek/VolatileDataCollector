#include "VSTriage.h"


PWSTR pwszCusrBuf = NULL;
size_t stCusrBufSize;

HCERTSTORE CUSROpenRootStore(DWORD dwStore)
{
	HCERTSTORE hCertStore;
	hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		(HCRYPTPROV_LEGACY)NULL,
		dwStore | (DWORD)CERT_STORE_READONLY_FLAG,
		L"Root"
	);
	return hCertStore;
}


BOOL CUSRGetCertThumbprint(PCCERT_CONTEXT pccertContext, PWSTR pwszThumbprint)
{
	if ((NULL == pccertContext) || (NULL == pwszThumbprint))
	{
		return FALSE;
	}
	BYTE certThumbPrintArr[CERT_SHA1_HASH_LENGTH] = {0};
	DWORD certThumbPrintSize = ARRAYSIZE(certThumbPrintArr);
	BOOL bRes;
	WCHAR pwszT1[2 * CERT_SHA1_HASH_LENGTH + 1] = {0};
	DWORD i;
	bRes = CertGetCertificateContextProperty(
		pccertContext,
		CERT_SHA1_HASH_PROP_ID,
		certThumbPrintArr,
		&certThumbPrintSize);
	if (!bRes)
	{
		StringCchCopy(pwszThumbprint, ARRAYSIZE(certThumbPrintArr), L"\0");
		return FALSE;
	}
	for (i = 0; i < ARRAYSIZE(certThumbPrintArr); i++)
	{
		WCHAR wcT[4] = {0};
		StringCchPrintfW(wcT, ARRAYSIZE(wcT), L"%02x", certThumbPrintArr[i]);
		StringCchCatW(pwszT1, ARRAYSIZE(pwszT1), wcT);
	}
	StringCchCopyW(pwszThumbprint, (ARRAYSIZE(pwszT1) + 1) * sizeof(WCHAR), pwszT1);
	return TRUE;
}


BOOL CUSRScan(DWORD dwStore)
{
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pccContext = NULL;
	DWORD dwTypePara = 0;
	DWORD i = 0;

	hCertStore = CUSROpenRootStore(dwStore);
	if (!hCertStore)
	{
		return FALSE;
	}
	while (NULL != (pccContext = CertEnumCertificatesInStore(hCertStore, pccContext)))
	{
		WCHAR pwszNameString2[SIZE_1KB];
		WCHAR pwszNameString[SIZE_1KB];
		CUSRGetCertThumbprint(pccContext, pwszNameString);
		StringCchPrintfW(pwszNameString2, ARRAYSIZE(pwszNameString2), L"\t%03d: %s\t", ++i, pwszNameString);
		StringCchCatW(pwszCusrBuf, stCusrBufSize / sizeof(WCHAR), pwszNameString2);
		CertGetNameStringW(pccContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, &dwTypePara, pwszNameString, SIZE_1KB);
		StringCchPrintfW(pwszNameString2, ARRAYSIZE(pwszNameString2), L"%s\r\n", pwszNameString);
		StringCchCatW(pwszCusrBuf, stCusrBufSize / sizeof(WCHAR), pwszNameString2);
	}
	CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
	return TRUE;
}


BOOL CUSRMain(void)
{
	BOOL bRes1;
	BOOL bRes2;
	StringCchCatW(pwszCusrBuf, stCusrBufSize / sizeof(WCHAR), L"Machine Root\r\n");
	bRes1 = CUSRScan(CERT_SYSTEM_STORE_LOCAL_MACHINE);
	StringCchCatW(pwszCusrBuf, stCusrBufSize / sizeof(WCHAR), L"Current User Root\r\n");
	bRes2 = CUSRScan(CERT_SYSTEM_STORE_CURRENT_USER);
	return (bRes1 && bRes2);
}


PWSTR CUSR_Output(void)
{
	wprintf(L"Listing Root Certs\r\n");
	stCusrBufSize = SIZE_16MB;

	ALLOCORCRASH(pwszCusrBuf, stCusrBufSize);

	AddCheckHeader(pwszCusrBuf, stCusrBufSize, L"Root Certs", FALSE);

	CUSRMain();
	ShrinkWcharBuffer(&pwszCusrBuf);
	return pwszCusrBuf;
}
