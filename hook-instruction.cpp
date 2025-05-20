#include <array>
#include <format>

#include <Windows.h>

class HookManager {
private:
	constexpr static std::intptr_t instruction_size{
#ifdef _WIN64
		12,
#else
		5
#endif
	};

	std::array<unsigned char, instruction_size> original_instruction, hook_instruction{
#ifdef _WIN64
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0
#else
		0xe9, 0x00, 0x00, 0x00, 0x00
#endif
	};
	void *original_function;
	DWORD old_protect{};

public:
	HookManager(void *original_function, void *hook_function)
		: original_function{ original_function }
	{
#ifdef _WIN64
		std::memcpy(hook_instruction.data() + 2, &hook_function, sizeof(hook_function));
#else
		auto offset{ reinterpret_cast<std::intptr_t>(hook_function) - reinterpret_cast<std::intptr_t>(original_function) - instruction_size };
		std::memcpy(hook_instruction.data() + 1, &offset, sizeof(offset));
#endif
		VirtualProtect(original_function, instruction_size, PAGE_EXECUTE_READWRITE, &old_protect);
		std::memcpy(original_instruction.data(), original_function, instruction_size);
	}

	~HookManager()
	{
		unhook();
		VirtualProtect(original_function, instruction_size, old_protect, &old_protect);
	}

	void hook() const
	{
		std::memcpy(original_function, hook_instruction.data(), instruction_size);
	}

	void unhook() const
	{
		std::memcpy(original_function, original_instruction.data(), instruction_size);
	}
};

#define API_NAME_HELPER(name) #name
#define API_NAME(name)		  TEXT(API_NAME_HELPER(name))

int WINAPI MessageBox_hook(
	HWND	hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT	uType);

static HookManager hook_manager(MessageBox, reinterpret_cast<void *>(MessageBox_hook));

int WINAPI MessageBox_hook(
	HWND	hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT	uType)
{
	::hook_manager.unhook();
	auto ret{ MessageBox(hWnd, std::format(TEXT("{} (hooked):\n{}"), API_NAME(MessageBox), lpText).c_str(), lpCaption, uType) };
	::hook_manager.hook();
	return ret;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			::hook_manager.hook();
			break;
		case DLL_PROCESS_DETACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return TRUE;
}
