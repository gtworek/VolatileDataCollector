#include "VSTriage.h"
//#define WINDOWS7BUILD TRUE

PNODE pnReportHead; // global variable - pointer to report head node.

BOOL SaveReport(PWCHAR wszFileName, PNODE pHead)
{
	HANDLE hFile;
	DWORD dwBytesWritten;

	hFile = CreateFile(
		wszFileName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL
	);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		return FALSE;
	}

	WriteFile(
		hFile,
		&BOM,
		2,
		&dwBytesWritten,
		NULL
	);

	PNODE temp;

	temp = pHead;
	while (temp != NULL)
	{
		WriteFile(
			hFile,
			temp->data,
			(DWORD)(wcslen(temp->data) * sizeof(WCHAR)),
			&dwBytesWritten,
			NULL
		);
		temp = temp->next;
	}
	CloseHandle(hFile);
	return TRUE;
}


PWSTR MyComputerName(void)
{
	PWSTR pwszData;
	DWORD dwChars = MAX_PATH; //overkill but works
	ALLOCORCRASH(pwszData, dwChars * sizeof(WCHAR));
	GetComputerNameExW(ComputerNamePhysicalNetBIOS, pwszData, &dwChars);
	return pwszData;
}


WCHAR wszOutputFileName[MAX_PATH] = L"\0";
WCHAR wszDumpFileName[MAX_PATH] = L"\0";
BOOL bMemDump = FALSE;

int wmain(int argc, WCHAR** argv, WCHAR** envp)
{
	UNREFERENCED_PARAMETER(envp);

#ifdef WINDOWS7BUILD
#pragma message("********** WINDOWS 7 BUILD **********")
	wprintf(L"\r\n********** WINDOWS 7 BUILD **********\r\n\r\n");
#endif

	BOOL bRes;
	pnReportHead = NULL;

	int i = 0;
	while (i < argc)
	{
		PWSTR pwszCurrentParam = argv[i];
		if (!_wcsicmp(L"-f", pwszCurrentParam))
		{
			i++;
			if (NULL != argv[i])
			{
				if (wcslen(argv[i]) > 0)
				{
					if (argv[i][0] == L'-')
					{
						continue; //next param name
					}

					errno_t err = wcsncpy_s(wszOutputFileName, ARRAYSIZE(wszOutputFileName), argv[i], _TRUNCATE);
					if (STRUNCATE == err)
					{
						wszOutputFileName[0] = L'\0';
					}
				}
			}
		}

		if (!_wcsicmp(L"-memdump", pwszCurrentParam))
		{
			bMemDump = TRUE;
			i++;
			if (NULL != argv[i])
			{
				if (wcslen(argv[i]) > 0)
				{
					if (argv[i][0] == L'-')
					{
						continue; //next param name
					}

					errno_t err = wcsncpy_s(wszDumpFileName, ARRAYSIZE(wszDumpFileName), argv[i], _TRUNCATE);
					if (STRUNCATE == err)
					{
						wszDumpFileName[0] = L'\0';
					}
				}
			}
		}
		i++;
	}

	PWSTR pwsz1 = MyComputerName();
	PWSTR pwsz2 = GetCurrentTimeZ();

	//default report name
	if (0 == wcslen(wszOutputFileName))
	{
		StringCchPrintfW(
			wszOutputFileName,
			ARRAYSIZE(wszOutputFileName),
			L"%s.%s.%s.txt",
			argv[0],
			pwsz1,
			pwsz2);
		for (int j = 3; j < (int)wcslen(wszOutputFileName); j++)
		{
			if (L':' == wszOutputFileName[j])
			{
				wszOutputFileName[j] = L'-';
			}
		}
	}

	//default dump name
	if (0 == wcslen(wszDumpFileName))
	{
		StringCchPrintfW(
			wszDumpFileName,
			ARRAYSIZE(wszDumpFileName),
			L"%s.%s.%s.dmp",
			argv[0],
			pwsz1,
			pwsz2);
		for (int j = 3; j < (int)wcslen(wszDumpFileName); j++)
		{
			if (L':' == wszDumpFileName[j])
			{
				wszDumpFileName[j] = L'-';
			}
		}
	}

	LocalFree(pwsz1);
	LocalFree(pwsz2);

	wprintf(L"\r\n");
	wprintf(L"Params:\r\n");
	wprintf(L"\tOutput file (-f): %s\r\n", wszOutputFileName);
#ifndef WINDOWS7BUILD
	wprintf(L"\tMemory dump (-memdump): %s\r\n", (bMemDump ? wszDumpFileName : L"(none)"));
#endif
	wprintf(L"\r\n");

	EnableAllPrivileges();

#ifndef WINDOWS7BUILD
	if (bMemDump)
	{
		wprintf(L"Dumping Memory\r\n");
		KernelDump(wszDumpFileName);
	}
#endif

	InsertAtOutputTail(HNM_Output());
	InsertAtOutputTail(TLV_Output());
	InsertAtOutputTail(TLM_Output());
	InsertAtOutputTail(TLM2_Output());
	InsertAtOutputTail(DRV_Output());
	InsertAtOutputTail(SET_Output());
	InsertAtOutputTail(CUSR_Output());
	InsertAtOutputTail(HND_Output());
	InsertAtOutputTail(ARPA_Output());
	InsertAtOutputTail(ICOA_Output());
	InsertAtOutputTail(ICOD_Output());
	InsertAtOutputTail(NANO_Output());
	InsertAtOutputTail(KLS_Output());

	bRes = SaveReport(wszOutputFileName, pnReportHead);
	if (!bRes)
	{
		DWORD dwError;
		dwError = GetLastError();
		wprintf(L"ERROR %i\r\n", dwError);
		return (int)dwError;
	}

	wprintf(L"Done.\r\n");
}
