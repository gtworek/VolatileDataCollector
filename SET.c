#include "VSTriage.h"

PWSTR SET_Output(void)
{
	PWSTR buf;
	size_t stBufSize;
	HRESULT hResult;
	PWSTR pwszFullEnvOrg;
	PWSTR pwszFullEnv;
	wprintf(L"Listing Environment\r\n");


	pwszFullEnvOrg = GetEnvironmentStringsW();
	pwszFullEnv = pwszFullEnvOrg;

	stBufSize = SIZE_16MB;
	buf = LocalAlloc(LPTR, stBufSize);
	CRASHIFNULLALLOC(buf);

	AddCheckHeader(buf, stBufSize, L"Environment Variables", TRUE);

	while (*pwszFullEnv)
	{
		hResult = StringCchCatW(buf, stBufSize / sizeof(WCHAR), pwszFullEnv);
		CHECKSTRINGHR(hResult);

		hResult = StringCchCatW(buf, stBufSize / sizeof(WCHAR), L"\r\n");
		CHECKSTRINGHR(hResult);

		pwszFullEnv += wcslen(pwszFullEnv) + 1; // include NULL
	}

	ShrinkWcharBuffer(&buf);
	return buf;
}
