
#include <winpr/crt.h>
#include <winpr/smartcard.h>

int TestSmartCardListReaders(int argc, char* argv[])
{
	LONG lStatus;
	LPTSTR pReader;
	SCARDCONTEXT hSC;
	LPTSTR pmszReaders = NULL;
	DWORD cch = SCARD_AUTOALLOCATE;

	lStatus = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC);

	if (lStatus != SCARD_S_SUCCESS)
	{
		printf("SCardEstablishContext failure: 0x%04X\n", (int) lStatus);
		return -1;
	}

	lStatus = SCardListReaders(hSC, NULL, (LPTSTR) &pmszReaders, &cch);

	if (lStatus != SCARD_S_SUCCESS)
	{
		if (lStatus == SCARD_E_NO_READERS_AVAILABLE)
		{
			printf("SCARD_E_NO_READERS_AVAILABLE\n");
		}
		else
		{
			return -1;
		}
	}
	else
	{
		pReader = pmszReaders;

		while (*pReader)
		{
			printf("Reader: %s\n", pReader);
			pReader = pReader + strlen((CHAR*) pReader) + 1;
		}

		lStatus = SCardFreeMemory(hSC, pmszReaders);

		if (lStatus != SCARD_S_SUCCESS)
			printf("Failed SCardFreeMemory\n");
	}

	SCardReleaseContext(hSC);

	return 0;
}
