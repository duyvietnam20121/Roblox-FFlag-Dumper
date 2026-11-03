#pragma once
// ---------------------------------------------------------------------------
// Memory.hpp - read-only access to another process (RAII, no raw globals).
//
// Design notes:
//  * Only PROCESS_VM_READ | PROCESS_QUERY_INFORMATION is requested
//    (least privilege - the dumper never writes to the target).
//  * Every read returns std::optional / bool, so a failed read can never be
//    mistaken for a valid value (the old read<T>() had UB on failure).
//  * Everything is inline, so the header is safe to include from many TUs.
// ---------------------------------------------------------------------------

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>

namespace Memory {

inline constexpr std::uintptr_t kMinUserPointer = 0x10000;
inline constexpr std::uintptr_t kMaxUserPointer = 0x00007FFFFFFFFFFFull;

// True when `p` looks like a canonical user-mode x64 pointer.
[[nodiscard]] constexpr bool IsUserPointer(std::uintptr_t p) noexcept {
    return p >= kMinUserPointer && p <= kMaxUserPointer;
}

// "0x1A2B" (or "0x1a2b" with upper = false) without touching std::cout's sticky flags.
[[nodiscard]] inline std::string ToHex(std::uintptr_t value, bool upper = true) {
    std::ostringstream ss;
    ss << "0x" << (upper ? std::uppercase : std::nouppercase) << std::hex << value;
    return ss.str();
}

struct ModuleInfo {
    std::uintptr_t base = 0;
    std::size_t size = 0;  // SizeOfImage
};

// Case-insensitive lookup of a process id by executable name. 0 = not found.
[[nodiscard]] inline DWORD FindProcessId(std::wstring_view exeName) {
    const std::wstring wanted(exeName);
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(wanted.c_str(), entry.szExeFile) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

class Process {
public:
    Process() = default;
    ~Process() { Detach(); }
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    bool Attach(DWORD pid) {
        Detach();
        handle_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!handle_) return false;
        pid_ = pid;
        return true;
    }

    void Detach() noexcept {
        if (handle_) CloseHandle(handle_);
        handle_ = nullptr;
        pid_ = 0;
    }

    [[nodiscard]] DWORD Pid() const noexcept { return pid_; }

    // Reads exactly `size` bytes or fails.
    [[nodiscard]] bool ReadBytes(std::uintptr_t address, void* buffer, std::size_t size) const noexcept {
        if (!handle_) return false;
        SIZE_T read = 0;
        return ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), buffer, size, &read) &&
               read == size;
    }

    template <typename T>
    [[nodiscard]] std::optional<T> Read(std::uintptr_t address) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "Read<T> needs a trivially copyable type");
        T value{};
        if (ReadBytes(address, &value, sizeof(T))) return value;
        return std::nullopt;
    }

    // Module (e.g. the main exe) base address and image size.
    [[nodiscard]] std::optional<ModuleInfo> FindModule(std::wstring_view moduleName) const {
        HANDLE snap = INVALID_HANDLE_VALUE;
        // ERROR_BAD_LENGTH happens while the target is still loading modules.
        for (int attempt = 0; attempt < 5; ++attempt) {
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
            if (snap != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
        }
        if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

        const std::wstring wanted(moduleName);
        std::optional<ModuleInfo> result;
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(wanted.c_str(), entry.szModule) == 0) {
                    result = ModuleInfo{reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
                                        static_cast<std::size_t>(entry.modBaseSize)};
                    break;
                }
            } while (Module32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return result;
    }

    // Full path of the target's executable (used to read its file version).
    [[nodiscard]] std::optional<std::wstring> ImagePath() const {
        if (!handle_) return std::nullopt;
        std::wstring buffer(MAX_PATH * 4, L'\0');
        DWORD length = static_cast<DWORD>(buffer.size());
        if (!QueryFullProcessImageNameW(handle_, 0, buffer.data(), &length)) return std::nullopt;
        buffer.resize(length);
        return buffer;
    }

    // Reads an MSVC x64 std::string located at `address`.
    //
    // Layout: +0x00 inline buffer / heap pointer, +0x10 size, +0x18 capacity.
    //  * capacity <= 15  -> text is stored inline (SSO) at +0x00
    //  * capacity >= 16  -> +0x00 is a heap pointer
    // `size` gives the exact length (no over-reading up to capacity, no
    // "cut at first NUL" guessing) and `size <= capacity` is a strong sanity
    // check that rejects random memory. Returns nullopt for anything that does
    // not look like a sane, non-empty string without embedded NULs.
    [[nodiscard]] std::optional<std::string> ReadMsvcString(std::uintptr_t address) const {
        constexpr std::uint64_t kMaxLength = 1000;
        constexpr std::uint64_t kMaxCapacity = 1u << 20;
        constexpr std::uint64_t kSsoCapacity = 15;

        struct Header {
            std::uint64_t size;
            std::uint64_t capacity;
        } header{};
        if (!ReadBytes(address + 0x10, &header, sizeof(header))) return std::nullopt;

        if (header.size == 0 || header.size > kMaxLength || header.size > header.capacity ||
            header.capacity > kMaxCapacity)
            return std::nullopt;

        std::uintptr_t data = address;
        if (header.capacity > kSsoCapacity) {
            const auto pointer = Read<std::uintptr_t>(address);
            if (!pointer || !IsUserPointer(*pointer)) return std::nullopt;
            data = *pointer;
        }

        std::string text(static_cast<std::size_t>(header.size), '\0');
        if (!ReadBytes(data, text.data(), text.size())) return std::nullopt;
        if (text.find('\0') != std::string::npos) return std::nullopt;
        return text;
    }

private:
    HANDLE handle_ = nullptr;
    DWORD pid_ = 0;
};

}  // namespace Memory
