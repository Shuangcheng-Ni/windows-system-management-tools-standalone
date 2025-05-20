#include <algorithm>
#include <print>
#include <unordered_map>

#include <Shlwapi.h>

using namespace std::literals;

#ifdef _DEBUG
#define LOG(fmt, ...) std::println("[" __FUNCTION__ "] " fmt __VA_OPT__(, ) __VA_ARGS__)
#else
#define LOG(...)
#endif

struct StringHasher {
	using is_transparent = std::true_type;

	constexpr static std::hash<std::string_view> hasher{};

	template <class T>
		requires std::convertible_to<T, std::string_view>
	constexpr auto operator()(T &&str) const noexcept
	{
		return hasher(std::forward<T>(str));
	}
};

class HookManager {
private:
	inline static std::unordered_map<HMODULE, std::unordered_map<std::string, void *, StringHasher, std::equal_to<>>> function_map;

	void   *IAT_entry_address{ nullptr }, *original_function, *hook_function;
	HMODULE target_dll_handle;

	friend FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName);

public:
	HookManager(std::string_view target_dll_name, std::string_view target_function_name, void *hook_function)
		: hook_function{ hook_function }
	{
		target_dll_handle = LoadLibraryA(target_dll_name.data());
		LOG("target dll: {} ({})", target_dll_name, static_cast<void *>(target_dll_handle));
		if (target_dll_handle == nullptr)
		{
			return;
		}

		void *target_function{ reinterpret_cast<void *>(GetProcAddress(target_dll_handle, target_function_name.data())) };
		LOG("target function: {} ({})", target_function_name, target_function);
		if (target_function == nullptr)
		{
			return;
		}

		LOG("hook function: {}", hook_function);
		function_map[target_dll_handle].emplace(target_function_name, hook_function);

		char *base{ reinterpret_cast<char *>(GetModuleHandle(nullptr)) };
		auto  dos_header{ reinterpret_cast<PIMAGE_DOS_HEADER>(base) };
		auto  nt_headers{ reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos_header->e_lfanew) };

		auto import_descriptor{ reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) };
		while (import_descriptor->Name != 0)
		{
			std::string_view dll_name(base + import_descriptor->Name);
			LOG("dll: {}", dll_name);
			if (std::ranges::equal(target_dll_name, dll_name, {}, ::tolower, ::tolower))
			{
				auto thunk{ reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_descriptor->FirstThunk) };
				while (thunk->u1.Function != 0)
				{
					auto &function{ reinterpret_cast<void *&>(thunk->u1.Function) };
					LOG("function: {}", function);
					if (function == target_function)
					{
						LOG("found target");
						IAT_entry_address = &function;
						original_function = function;
						return;
					}
					++thunk;
				}
				return;
			}
			++import_descriptor;
		}

		auto delayload_descriptor{ reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress) };
		while (delayload_descriptor->DllNameRVA != 0)
		{
			std::string_view dll_name(base + delayload_descriptor->DllNameRVA);
			LOG("dll: {} (delay load)", dll_name);
			if (std::ranges::equal(target_dll_name, dll_name, {}, ::tolower, ::tolower))
			{
				auto name_thunk{ reinterpret_cast<PIMAGE_THUNK_DATA>(base + delayload_descriptor->ImportNameTableRVA) };
				auto address_thunk{ reinterpret_cast<PIMAGE_THUNK_DATA>(base + delayload_descriptor->ImportAddressTableRVA) };
				while (name_thunk->u1.AddressOfData != 0)
				{
					if ((name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0)
					{
						std::string_view function_name(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + name_thunk->u1.AddressOfData)->Name);
						LOG("function: {} (delay load)", function_name);
						if (target_function_name == function_name)
						{
							LOG("found target (delay load)");
							auto &function{ reinterpret_cast<void *&>(address_thunk->u1.Function) };
							IAT_entry_address = &function;
							original_function = function;
							return;
						}
					}
					++name_thunk;
					++address_thunk;
				}
				return;
			}
			++delayload_descriptor;
		}
	}

	HookManager(const HookManager &) = delete;

	HookManager(HookManager &&other) noexcept
		: IAT_entry_address{ std::exchange(other.IAT_entry_address, nullptr) },
		  original_function{ other.original_function },
		  hook_function{ other.hook_function },
		  target_dll_handle{ std::exchange(other.target_dll_handle, nullptr) }
	{
		LOG();
	}

	~HookManager()
	{
		LOG();
		unhook();
		if (target_dll_handle != nullptr)
		{
			LOG("FreeLibrary");
			FreeLibrary(target_dll_handle);
		}
	}

	void hook() const
	{
		LOG("IAT address: {}", IAT_entry_address);
		if (valid())
		{
			LOG("from: {}", *reinterpret_cast<void **>(IAT_entry_address));
			DWORD old_protect{};
			VirtualProtect(IAT_entry_address, sizeof(hook_function), PAGE_READWRITE, &old_protect);
			std::memcpy(IAT_entry_address, &hook_function, sizeof(hook_function));
			VirtualProtect(IAT_entry_address, sizeof(hook_function), old_protect, &old_protect);
			LOG("to: {}", *reinterpret_cast<void **>(IAT_entry_address));
		}
	}

	void unhook() const
	{
		LOG("IAT address: {}", IAT_entry_address);
		if (valid())
		{
			LOG("from: {}", *reinterpret_cast<void **>(IAT_entry_address));
			DWORD old_protect{};
			VirtualProtect(IAT_entry_address, sizeof(original_function), PAGE_READWRITE, &old_protect);
			std::memcpy(IAT_entry_address, &original_function, sizeof(original_function));
			VirtualProtect(IAT_entry_address, sizeof(original_function), old_protect, &old_protect);
			LOG("to: {}", *reinterpret_cast<void **>(IAT_entry_address));
		}
	}

	bool valid() const noexcept { return IAT_entry_address != nullptr; }
};

int WINAPI MessageBoxW_hook(
	HWND	hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT	uType)
{
	return MessageBoxW(hWnd, std::format(L"MessageBoxW (hooked):\n{}", lpText).c_str(), lpCaption, uType);
}

HINSTANCE WINAPI ShellExecuteW_hook(
	HWND	hwnd,
	LPCWSTR lpOperation,
	LPCWSTR lpFile,
	LPCWSTR lpParameters,
	LPCWSTR lpDirectory,
	INT		nShowCmd)
{
	int option{ IDOK };
	if (lpOperation != nullptr && lpOperation == L"open"sv)
	{
		std::wstring_view url{};
		if (lpFile != nullptr && PathIsURLW(lpFile))
		{
			url = lpFile;
		}
		else if (lpParameters != nullptr && PathIsURLW(lpParameters))
		{
			url = lpParameters;
		}
		if (!url.empty())
		{
			option = MessageBoxW(nullptr, std::format(L"Open URL:\n{}", url).c_str(), L"ShellExecuteW", MB_OKCANCEL);
		}
	}
	return option == IDCANCEL ? nullptr : ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

FARPROC WINAPI GetProcAddress_hook(
	HMODULE hModule,
	LPCSTR	lpProcName)
{
	if (auto module_iter{ HookManager::function_map.find(hModule) }; module_iter != HookManager::function_map.end())
	{
		if (auto function_iter{ module_iter->second.find(lpProcName) }; function_iter != module_iter->second.end())
		{
			LOG("{}: found", lpProcName);
			return reinterpret_cast<FARPROC>(function_iter->second);
		}
	}
	LOG("{}: not found", lpProcName);
	return GetProcAddress(hModule, lpProcName);
}

static HookManager hooks[]{
	{ "user32.dll"sv, "MessageBoxW"sv, reinterpret_cast<void *>(MessageBoxW_hook) },
	{ "shell32.dll"sv, "ShellExecuteW"sv, reinterpret_cast<void *>(ShellExecuteW_hook) },
	{ "kernel32.dll"sv, "GetProcAddress"sv, reinterpret_cast<void *>(GetProcAddress_hook) },
};

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			LOG("DLL_PROCESS_ATTACH");
			std::ranges::for_each(::hooks, &HookManager::hook);
			break;
		case DLL_PROCESS_DETACH:
			LOG("DLL_PROCESS_DETACH");
			break;
		case DLL_THREAD_ATTACH:
			LOG("DLL_THREAD_ATTACH");
			break;
		case DLL_THREAD_DETACH:
			LOG("DLL_THREAD_DETACH");
			break;
	}
	return TRUE;
}
