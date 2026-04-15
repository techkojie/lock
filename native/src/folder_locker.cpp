/*
 * folder_locker.cpp
 * FolderLocker Native DLL
 *
 * Provides direct Windows Security API calls for
 * DACL manipulation — locking and unlocking folders
 * by modifying their Access Control Lists.
 *
 * Compiled as a DLL and loaded by Python via ctypes.
 * Python calls our clean simple functions.
 * We handle all the raw Windows API complexity.
 *
 * Compiler: GCC 15.2.0 via MinGW64
 * Target: Windows x64
 */

// Windows headers must come first
// windows.h pulls in the core Windows API
// aclapi.h provides the security/ACL functions
// sddl.h provides SDDL string conversion functions
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

// Standard C++ headers
#include <algorithm>
#include <string>
#include <vector>
#include <stdexcept>

// ─────────────────────────────────────────────────────
// DLL export macro
// LOCKER_API marks functions we want Python to see.
// __declspec(dllexport) tells the linker to make
// this function visible outside the DLL.
// Without this the function is private to the DLL
// and ctypes cannot find or call it.
// extern "C" prevents C++ name mangling —
// C++ compilers decorate function names with type
// information which makes them impossible to find
// by their original name. extern "C" keeps the
// name exactly as written so ctypes can find it.
// ─────────────────────────────────────────────────────
#define LOCKER_API extern "C" __declspec(dllexport)

// ─────────────────────────────────────────────────────
// Internal helper — read DACL as SDDL string
//
// Takes a folder path and returns its current
// security descriptor as an SDDL string.
// The caller is responsible for freeing the
// returned buffer using free_sddl_buffer().
//
// Returns nullptr on failure.
// Sets Windows last error code on failure.
// ─────────────────────────────────────────────────────
static wchar_t *_read_sddl(const wchar_t *path)
{
    // These will receive pointers written by
    // GetNamedSecurityInfoW — Windows allocates
    // the memory and we must free it with LocalFree
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;

    // Read the current security descriptor from the folder
    // SE_FILE_OBJECT — tells Windows this is a file/folder
    // DACL_SECURITY_INFORMATION — we only want the DACL
    // not the owner, group, or audit rules
    DWORD result = GetNamedSecurityInfoW(
        path,                      // folder path
        SE_FILE_OBJECT,            // object type
        DACL_SECURITY_INFORMATION, // what we want
        nullptr,                   // owner SID (not needed)
        nullptr,                   // group SID (not needed)
        &dacl,                     // receives DACL pointer
        nullptr,                   // SACL (not needed)
        &sd                        // receives full descriptor
    );

    if (result != ERROR_SUCCESS)
    {
        SetLastError(result);
        return nullptr;
    }

    // Convert binary security descriptor to SDDL text string
    // SDDL_REVISION_1 is always 1 — the only revision
    // DACL_SECURITY_INFORMATION — only include the DACL
    // in the output string, not owner or audit info
    wchar_t *sddl_string = nullptr;
    BOOL converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd,                        // binary descriptor
        SDDL_REVISION_1,           // always 1
        DACL_SECURITY_INFORMATION, // what to include
        &sddl_string,              // output SDDL string
        nullptr                    // optional length (not needed)
    );

    // Free the security descriptor Windows allocated
    // We must do this before returning or we leak memory
    LocalFree(sd);

    if (!converted)
    {
        return nullptr;
    }

    // sddl_string is Windows-allocated memory
    // caller must free it with free_sddl_buffer()
    return sddl_string;
}

// ─────────────────────────────────────────────────────
// Internal helper — apply SDDL string to a folder
//
// Takes a folder path and an SDDL string and
// writes the corresponding DACL to the folder.
// Used by both lock_folder and unlock_folder.
//
// Returns ERROR_SUCCESS on success.
// Returns Windows error code on failure.
// ─────────────────────────────────────────────────────
static DWORD _apply_sddl(
    const wchar_t *path,
    const wchar_t *sddl)
{
    PSECURITY_DESCRIPTOR sd = nullptr;
    BOOL converted = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        &sd,
        nullptr);

    if (!converted)
    {
        DWORD err = GetLastError();
        // Write debug to a temp file so Python can read it
        return err ? err : ERROR_INVALID_DATA;
    }

    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;

    BOOL got_dacl = GetSecurityDescriptorDacl(
        sd,
        &dacl_present,
        &dacl,
        &dacl_defaulted);

    if (!got_dacl || !dacl_present)
    {
        LocalFree(sd);
        return ERROR_INVALID_DATA;
    }

    DWORD result = SetNamedSecurityInfoW(
        const_cast<wchar_t *>(path),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);

    LocalFree(sd);

    return result;
}
// ─────────────────────────────────────────────────────
// Internal helper — collect all subfolders recursively
//
// Walks a directory tree and collects all subfolder
// paths into a vector of wide strings.
// Used by lock_recursive and unlock_recursive.
// ─────────────────────────────────────────────────────
static void _collect_subfolders(
    const std::wstring &root,
    std::vector<std::wstring> &folders)
{
    // Build the search pattern — root\*
    // WIN32_FIND_DATAW holds info about each found item
    std::wstring pattern = root + L"\\*";
    WIN32_FIND_DATAW find_data;

    HANDLE find_handle = FindFirstFileW(
        pattern.c_str(),
        &find_data);

    if (find_handle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        // Skip . and .. (current and parent directory)
        if (wcscmp(find_data.cFileName, L".") == 0 ||
            wcscmp(find_data.cFileName, L"..") == 0)
        {
            continue;
        }

        // Only process directories not files
        if (find_data.dwFileAttributes &
            FILE_ATTRIBUTE_DIRECTORY)
        {

            std::wstring subfolder =
                root + L"\\" + find_data.cFileName;

            // Add this subfolder to our collection
            folders.push_back(subfolder);

            // Recurse into it to find its subfolders
            _collect_subfolders(subfolder, folders);
        }

    } while (FindNextFileW(find_handle, &find_data));

    FindClose(find_handle);
}

// ─────────────────────────────────────────────────────
// PUBLIC API — functions exported for Python to call
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
// snapshot_dacl
//
// Read the current DACL from a folder and return
// it as an SDDL string that Python can save to disk.
//
// Parameters:
//   path     — wide string path to the folder
//   out_buf  — buffer Python provides to receive result
//   buf_size — size of that buffer in characters
//
// Returns:
//   1 on success (out_buf contains SDDL string)
//   0 on failure (call GetLastError for details)
//
// Why output buffer instead of returning a pointer:
//   Returning a pointer across DLL boundaries is
//   dangerous — Python and the DLL may use different
//   memory allocators. If Python tries to free memory
//   the DLL allocated it can crash the process.
//   Instead we write into a buffer Python owns.
//   Python allocates it, we fill it, Python frees it.
//   Safe. No cross-boundary memory ownership issues.
// ─────────────────────────────────────────────────────
LOCKER_API int snapshot_dacl(
    const wchar_t *path,
    wchar_t *out_buf,
    int buf_size)
{
    wchar_t *sddl = _read_sddl(path);
    if (!sddl)
    {
        return 0;
    }

    // Copy SDDL into Python's buffer
    // wcsncpy_s is the safe version of wcsncpy
    // it prevents buffer overflows
    errno_t copy_result = wcsncpy_s(
        out_buf,
        buf_size,
        sddl,
        _TRUNCATE);

    // Free the Windows allocated SDDL string
    LocalFree(sddl);

    return (copy_result == 0) ? 1 : 0;
}

// ─────────────────────────────────────────────────────
// lock_folder
//
// Lock a single folder by applying DENY Everyone ACL.
// Also snapshots the original DACL first and writes
// it into out_sddl so Python can save it for unlock.
//
// The SDDL we apply:
//   D:PAI(D;;FA;;;WD)
//   D:   = DACL section
//   P    = Protected (no inheritance from parent)
//   AI   = Allow inherited ACEs to propagate to children
//   D    = Deny
//   FA   = File All access (everything)
//   WD   = World (Everyone)
//
// Parameters:
//   path      — wide string path to the folder
//   out_sddl  — buffer to receive original SDDL snapshot
//   buf_size  — size of that buffer in characters
//
// Returns:
//   1 on success
//   0 on failure
// ─────────────────────────────────────────────────────
LOCKER_API int lock_folder(
    const wchar_t *path,
    wchar_t *out_sddl,
    int buf_size)
{
    // First snapshot the current DACL
    // We must save it before overwriting
    wchar_t *original_sddl = _read_sddl(path);
    if (!original_sddl)
    {
        return 0;
    }

    // Copy snapshot into Python's buffer
    errno_t copy_result = wcsncpy_s(
        out_sddl,
        buf_size,
        original_sddl,
        _TRUNCATE);
    LocalFree(original_sddl);

    if (copy_result != 0)
    {
        return 0;
    }

    // Apply the DENY Everyone DACL
    DWORD result = _apply_sddl(path, L"D:PAI(D;;FA;;;WD)");
    return (result == ERROR_SUCCESS) ? 1 : 0;
}

// ─────────────────────────────────────────────────────
// unlock_folder
//
// Restore a folder's original DACL from a saved
// SDDL snapshot. Reverses what lock_folder did.
//
// Parameters:
//   path          — wide string path to the folder
//   original_sddl — the SDDL string saved at lock time
//
// Returns:
//   1 on success
//   0 on failure
// ─────────────────────────────────────────────────────
LOCKER_API int unlock_folder(
    const wchar_t *path,
    const wchar_t *original_sddl)
{
    DWORD result = _apply_sddl(path, original_sddl);
    return (result == ERROR_SUCCESS) ? 1 : 0;
}

// ─────────────────────────────────────────────────────
// lock_recursive
//
// Lock a folder and all its subfolders.
// Snapshots only the top level DACL — we use the
// same SDDL for all subfolders on unlock since
// they all get the same DENY Everyone applied.
//
// Parameters:
//   path      — wide string path to the root folder
//   out_sddl  — buffer to receive original SDDL
//   buf_size  — size of that buffer in characters
//
// Returns:
//   1 on success
//   0 on failure
// ─────────────────────────────────────────────────────
LOCKER_API int lock_recursive(
    const wchar_t *path,
    wchar_t *out_sddl,
    int buf_size)
{
    // Lock the top level folder first
    // This also snapshots the original DACL
    int top_result = lock_folder(path, out_sddl, buf_size);
    if (!top_result)
    {
        return 0;
    }

    // Collect all subfolders
    std::vector<std::wstring> subfolders;
    _collect_subfolders(path, subfolders);

    // Lock each subfolder
    // We use a dummy buffer for subfolders since
    // we only need the top level DACL snapshot
    wchar_t dummy_buf[4096];
    for (const auto &subfolder : subfolders)
    {
        lock_folder(subfolder.c_str(), dummy_buf, 4096);
        // Continue even if one subfolder fails
        // We lock as many as we can
    }

    return 1;
}

// ─────────────────────────────────────────────────────
// unlock_recursive
//
// Unlock a folder and all its subfolders.
// Applies the saved original SDDL to every folder.
// Unlocks deepest subfolders first so we always
// have filesystem access to work our way up.
//
// Parameters:
//   path          — wide string path to the root folder
//   original_sddl — the SDDL saved at lock time
//
// Returns:
//   1 on success
//   0 on failure
// ─────────────────────────────────────────────────────
LOCKER_API int unlock_recursive(
    const wchar_t *path,
    const wchar_t *original_sddl)
{
    // Collect all subfolders first
    std::vector<std::wstring> subfolders;
    _collect_subfolders(path, subfolders);

    // Sort by depth — deepest first
    // Longer path = deeper in the tree
    // We must unlock children before parents
    // so we have access to navigate the tree
    std::sort(
        subfolders.begin(),
        subfolders.end(),
        [](const std::wstring &a, const std::wstring &b)
        {
            return a.length() > b.length();
        });

    // Unlock all subfolders deepest first
    for (const auto &subfolder : subfolders)
    {
        unlock_folder(subfolder.c_str(), original_sddl);
    }

    // Unlock the top level folder last
    int result = unlock_folder(path, original_sddl);
    return result;
}

// ─────────────────────────────────────────────────────
// get_last_error
//
// Returns the Windows last error code.
// Python calls this when a function returns 0
// to find out what went wrong.
// ─────────────────────────────────────────────────────
LOCKER_API DWORD get_last_error()
{
    return GetLastError();
}

// ─────────────────────────────────────────────────────
// DLL entry point
//
// Called by Windows when the DLL is loaded or unloaded.
// We do not need any special initialization or cleanup
// so we just return TRUE to tell Windows loading succeeded.
//
// DLL_PROCESS_ATTACH — DLL being loaded into a process
// DLL_PROCESS_DETACH — DLL being unloaded
// DLL_THREAD_ATTACH  — new thread created in process
// DLL_THREAD_DETACH  — thread exiting in process
// ─────────────────────────────────────────────────────
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}