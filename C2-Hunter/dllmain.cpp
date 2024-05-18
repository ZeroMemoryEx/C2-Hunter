#include "pch.h"
#include <Windows.h>
#include <winbase.h>;
#include "MinHook.h"
#include <unknwn.h>
#include <iostream>
#include <wininet.h>
#include <Urlmon.h>
#include <windns.h>
#include <ws2tcpip.h>

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment (lib, "Ws2_32.lib")


HRESULT FURLOpenStreamA(
    LPUNKNOWN            pCaller,
    LPCSTR               szURL,
    _Reserved_ DWORD                dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    MH_DisableHook(&URLOpenStreamA);
    std::cout <<
        "URL  : " << szURL <<
        std::endl;
    HRESULT ret = URLOpenStreamA(
        pCaller,
        szURL,
        dwReserved,
        lpfnCB
    );

    MH_EnableHook(&URLOpenStreamA);
    return (ret);
}

HRESULT FURLDownloadToFile(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD                dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    MH_DisableHook(&URLDownloadToFile);
    std::cout <<
        "URL  : " << szURL <<
        "file path :" << szFileName <<
        std::endl;
    HRESULT ret = URLDownloadToFile(
        pCaller,
        szURL,
        szFileName,
        dwReserved,
        lpfnCB
    );
    MH_EnableHook(&URLDownloadToFile);
    return (ret);
}


BOOL FInternetWriteFile(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    MH_DisableHook(&InternetWriteFile);

    DWORD nbytes;
    BOOL ret = InternetWriteFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten
    );
    nbytes = *lpdwNumberOfBytesWritten;
    char* buffer = (char*)lpBuffer;
    printf("%s", buffer);
    MH_EnableHook(&InternetWriteFile);
    return (ret);

}

HINTERNET WINAPI FInternetConnect(HINTERNET hInternet, LPCTSTR lpszServerName, INTERNET_PORT nServerPort, LPCTSTR lpszUserName, LPCTSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD dwContext)
{
    MH_DisableHook(&InternetConnect);
    std::cout
        << "Server Name" << lpszServerName
        << std::endl;
    HINTERNET ret = InternetConnect(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    MH_EnableHook(&InternetConnect);
    return (ret);

}

BOOL FInternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    MH_DisableHook(&InternetReadFile);

    DWORD nbytes;
    BOOL ret = InternetReadFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead
    );
    char* buffer = (char*)lpBuffer;
    printf("%s", buffer);
    MH_EnableHook(&InternetReadFile);
    return (ret);
}

BOOL FInternetReadFileExA(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
) {
    MH_DisableHook(&InternetReadFileExA);

    BOOL ret = InternetReadFileExA(
        hFile,
        lpBuffersOut,
        dwFlags,
        dwContext
    );

    printf("%.*s \n", lpBuffersOut->dwBufferLength, lpBuffersOut->lpvBuffer);
    printf("%s \n", lpBuffersOut->lpcszHeader);
    MH_EnableHook(&InternetReadFileExA);
    return (ret);
}

HINTERNET FInternetOpenUrlA(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    MH_DisableHook(&InternetOpenUrlA);
    LPWSTR wstr = new WCHAR[255];
    MultiByteToWideChar(CP_ACP, 0, lpszUrl, -1, wstr, 255);
    OutputDebugStringW(wstr);
    std::cout <<
        "HTTP verb : " << lpszUrl <<
        "target Object :" << lpszHeaders <<
        std::endl;
    HINTERNET ret = InternetOpenUrlA(
        hInternet,
        lpszUrl,
        lpszHeaders,
        dwHeadersLength,
        dwFlags,
        dwContext);
    MH_EnableHook(&InternetOpenUrlA);
    return (ret);
}

UINT FWinExec(
    LPCSTR lpCmdLine,
    UINT   uCmdShow
)
{
    MH_DisableHook(&WinExec);
    LPWSTR wstr = new WCHAR[255];
    MultiByteToWideChar(CP_ACP, 0, lpCmdLine, -1, wstr, 255);
    OutputDebugStringW(wstr);
    std::cout << wstr << std::endl;
    UINT ret = WinExec(lpCmdLine, uCmdShow);
    MH_EnableHook(&WinExec);
    return (ret);
}

HINTERNET FHttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    MH_DisableHook(&HttpOpenRequestA);
    std::cout <<
        "HTTP verb : " << lpszVerb <<
        "target Object :" << lpszObjectName <<
        std::endl;
    HINTERNET ret = HttpOpenRequestA(
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferrer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext);
    MH_EnableHook(&HttpOpenRequestA);
    return (ret);
}

HINTERNET FInternetConnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
)
{
    MH_DisableHook(&InternetConnectA);
    LPWSTR wstr = new WCHAR[255];
    MultiByteToWideChar(CP_ACP, 0, lpszServerName, -1, wstr, 255);
    OutputDebugStringW(wstr);
    std::cout <<
        "host name : " << lpszServerName <<
        "Username :" << lpszUserName <<
        "Password :" << lpszPassword <<
        std::endl;

    HINTERNET ret = InternetConnectA(
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUserName,
        lpszPassword,
        dwService,
        dwFlags,
        dwContext);

    MH_EnableHook(&InternetConnectA);
    return (ret);
}

DNS_STATUS FDnsQueryEx(
    PDNS_QUERY_REQUEST pQueryRequest,
    PDNS_QUERY_RESULT  pQueryResults,
    PDNS_QUERY_CANCEL  pCancelHandle
)
{
    MH_DisableHook(&DnsQueryEx);

    if (pQueryRequest->QueryName)
    {
        OutputDebugStringW(pQueryRequest->QueryName);
        std::cout <<
            "DNS name : " << pQueryRequest->QueryName <<
            std::endl;
    }
    else
        std::cout << "local machine name" << std::endl;
    DNS_STATUS ret = DnsQueryEx(
        pQueryRequest,
        pQueryResults,
        pCancelHandle);

    MH_EnableHook(&DnsQueryEx);

    return (ret);
}


DNS_STATUS FDnsQuery_A(
    PCSTR       pszName,
    WORD        wType,
    DWORD       Options,
    PVOID       pExtra,
    PDNS_RECORD* ppQueryResults,
    PVOID* pReserved
)
{
    MH_DisableHook(&DnsQuery_A);
    LPWSTR wstr = new WCHAR[255];
    MultiByteToWideChar(CP_ACP, 0, pszName, -1, wstr, 255);
    OutputDebugStringW(wstr);
    std::cout <<
        "DNS name : " << pszName <<
        std::endl;

    DNS_STATUS ret = DnsQuery_A(
        pszName,
        wType,
        Options,
        pExtra,
        ppQueryResults,
        pReserved);

    MH_EnableHook(&DnsQuery_A);

    return (ret);
}

int WSAAPI Fakegetaddrinfo(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult
)
{
    // Log input parameters
    printf("Fakegetaddrinfo called with:\n");
    printf("  pNodeName: %s\n", pNodeName ? pNodeName : "(null)");
    printf("  pServiceName: %s\n", pServiceName ? pServiceName : "(null)");

    MH_DisableHook(&getaddrinfo);

    int ret = getaddrinfo(pNodeName, pServiceName, pHints, ppResult);


    // Re-enable hook
    MH_EnableHook(&getaddrinfo);

    return ret;
}

int WSAAPI FakeGetAddrInfoW(
    PCWSTR          pNodeName,
    PCWSTR          pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW* ppResult
)
{
    printf("FakeGetAddrInfoW called with:\n");
    printf("  pNodeName: %ws\n", pNodeName ? pNodeName : L"(null)");
    printf("  pServiceName: %ws\n", pServiceName ? pServiceName : L"(null)");

    MH_DisableHook(&GetAddrInfoW);

    int ret = GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);


    MH_EnableHook(&GetAddrInfoW);

    return ret;
}

int start()
{
    AllocConsole();

    FILE* f = new FILE;

    freopen_s(&f, "CONOUT$", "w", stdout);

    SetConsoleTitle(L"C2-Hunter");

    if (MH_Initialize() != MH_OK)
    {
        return (-1);
    }

    MH_CreateHook(&InternetConnect, &FInternetConnect, NULL);

    MH_CreateHook(&InternetConnectA, &FInternetConnectA, NULL);

    MH_CreateHook(&HttpOpenRequestA, &FHttpOpenRequestA, NULL);

    MH_CreateHook(&WinExec, &FWinExec, NULL);

    MH_CreateHook(&InternetOpenUrlA, &FInternetOpenUrlA, NULL);

    MH_CreateHook(&InternetReadFile, &FInternetReadFile, NULL);

    MH_CreateHook(&InternetReadFileExA, &FInternetReadFileExA, NULL);

    MH_CreateHook(&InternetWriteFile, &FInternetWriteFile, NULL);

    MH_CreateHook(&URLDownloadToFile, &FURLDownloadToFile, NULL);

    MH_CreateHook(&URLOpenStreamA, &FURLOpenStreamA, NULL);

    MH_CreateHook(&DnsQuery_A, &FDnsQuery_A, NULL);

    MH_CreateHook(&DnsQueryEx, &FDnsQueryEx, NULL);

    //
    MH_CreateHook(&getaddrinfo, &Fakegetaddrinfo, NULL); 
    if (MH_EnableHook(&getaddrinfo) != MH_OK)
    {
        return (-1);
    }

    MH_CreateHook(&GetAddrInfoW, &FakeGetAddrInfoW, NULL);
        if (MH_EnableHook(&GetAddrInfoW) != MH_OK)
        {
            return (-1);
        }

    //


    if (MH_EnableHook(&DnsQueryEx) != MH_OK)
    {
        return (-1);
    }

    if (MH_EnableHook(&InternetConnect) != MH_OK || MH_EnableHook(&DnsQuery_A) != MH_OK)
    {
        return (-1);
    }

    if (MH_EnableHook(&InternetConnectA) != MH_OK || MH_EnableHook(&HttpOpenRequestA))
    {
        return (-1);
    }

    if (MH_EnableHook(&WinExec) != MH_OK || MH_EnableHook(&InternetOpenUrlA))
    {
        return (-1);
    }

    if (MH_EnableHook(&InternetReadFile) != MH_OK || MH_EnableHook(&InternetReadFileExA))
    {
        return (-1);
    }

    if (MH_EnableHook(&InternetWriteFile) != MH_OK || MH_EnableHook(&URLDownloadToFile))
    {
        return (-1);
    }

    if (MH_EnableHook(&URLOpenStreamA) != MH_OK)
    {
        return (-1);
    }

    return (0);
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        start();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return (TRUE);
}
