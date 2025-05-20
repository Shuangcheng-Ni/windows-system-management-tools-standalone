#if !defined(UNICODE) && !defined(_UNICODE)
#define tstring		 string
#define tstring_view string_view
#define tprint		 std::print
#define tprintln	 std::println

#else
#ifndef UNICODE
#define UNICODE
#elifndef _UNICODE
#define _UNICODE
#endif

#define tstring		 wstring
#define tstring_view wstring_view
#define tprint		 stdext::wprint
#define tprintln	 stdext::wprintln

#endif

#include <filesystem>
#include <print>
#include <source_location>
#include <stacktrace>

#define NOMINMAX
#include <Windows.h>
#include <tchar.h>

using namespace std::literals;

namespace stdext {
template <class... Ts>
inline void wprint(const ::std::wformat_string<Ts...> fmt, Ts &&...args)
{
	auto wstr{ ::std::format(fmt, ::std::forward<decltype(args)>(args)...) };
	auto len{ WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, nullptr) };

	::std::string str(len, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.length()), str.data(), len, nullptr, nullptr);
	::std::print("{}", str);
}

template <class... Ts>
inline void wprintln(const ::std::wformat_string<Ts...> fmt, Ts &&...args)
{
	wprint(fmt, ::std::forward<decltype(args)>(args)...);
	::std::println();
}
} // namespace stdext

[[noreturn]] inline void throw_last_error(std::string_view		 reason		= ""sv,
										  std::source_location	 location	= std::source_location::current(),
										  const std::stacktrace &stacktrace = std::stacktrace::current())
{
	if (reason.empty())
	{
		reason = location.function_name();
	}
	throw std::runtime_error(
		std::format("{}: {:#010x}\nFile: {}\nLine: {}\nFunction: {}\nStacktrace:\n{}",
					reason, GetLastError(), location.file_name(), location.line(), location.function_name(), stacktrace));
}

template <class Ptr, auto CleanUp, auto InvalidPtr = Ptr{ nullptr }>
	requires std::is_pointer_v<Ptr> && std::invocable<decltype(CleanUp), Ptr>
class Guard : public std::unique_ptr<std::remove_pointer_t<Ptr>, void (*)(Ptr) noexcept> {
protected:
	using SmartPtr = std::unique_ptr<std::remove_pointer_t<Ptr>, void (*)(Ptr) noexcept>;

	inline static const auto invalid_ptr{ reinterpret_cast<Ptr>(InvalidPtr) };

	static void clean_up(Ptr ptr) noexcept
	{
		if (ptr != invalid_ptr)
		{
			CleanUp(ptr);
		}
	}

	SmartPtr &get_smart_ptr() noexcept { return *this; }

public:
	Guard() noexcept
		: SmartPtr(invalid_ptr, clean_up) {}
	explicit Guard(Ptr ptr) noexcept
		: SmartPtr(ptr, clean_up) {}

	Guard &operator=(Ptr ptr) noexcept
	{
		this->~Guard();
		new (this) Guard(ptr);
		return *this;
	}

	operator Ptr() const noexcept { return SmartPtr::get(); }

	auto operator&() noexcept { return std::inout_ptr(*this); }

	bool valid() const noexcept { return SmartPtr::get() != invalid_ptr; }
};

using Handle = Guard<HANDLE, CloseHandle>;

using ProcessHandle = Handle;

class ThreadHandle : public Handle {
public:
	using Handle::Handle;
	using Handle::operator=;

	void join() const
	{
		if (valid())
		{
			WaitForSingleObject(*this, INFINITE);
		}
		else
		{
			throw_last_error();
		}
	}
};

class RemoteMemory {
private:
	HANDLE process;
	LPVOID address;
	SIZE_T size;

public:
	RemoteMemory(HANDLE process, SIZE_T size, DWORD type = MEM_COMMIT, DWORD protect = PAGE_READWRITE)
		: process{ process },
		  address{ VirtualAllocEx(process, nullptr, size, type, protect) },
		  size{ size }
	{
		if (address == nullptr)
		{
			throw_last_error("VirtualAllocEx"sv);
		}
	}

	~RemoteMemory()
	{
		if (VirtualFreeEx(process, address, 0, MEM_RELEASE) == FALSE)
		{
			throw_last_error("VirtualFreeEx"sv);
		}
	}

	LPVOID get_address(std::ptrdiff_t offset = 0) const noexcept
	{
		return static_cast<char *>(address) + offset;
	}

	SIZE_T read(LPVOID buffer, std::ptrdiff_t offset = 0, SIZE_T len = std::numeric_limits<SIZE_T>::max()) const
	{
		if (offset < 0 || offset >= static_cast<std::ptrdiff_t>(size))
		{
			throw_last_error();
		}

		len = std::min(len, size - offset);
		if (ReadProcessMemory(process, get_address(offset), buffer, len, &len) == FALSE)
		{
			throw_last_error("ReadProcessMemory"sv);
		}
		return len;
	}

	SIZE_T write(LPCVOID buffer, std::ptrdiff_t offset = 0, SIZE_T len = std::numeric_limits<SIZE_T>::max()) const
	{
		if (offset < 0 || offset >= static_cast<std::ptrdiff_t>(size))
		{
			throw_last_error();
		}

		len = std::min(len, size - offset);
		if (WriteProcessMemory(process, get_address(offset), buffer, len, &len) == FALSE)
		{
			throw_last_error("WriteProcessMemory"sv);
		}
		return len;
	}
};

struct GetRemoteModuleHandleMessage {
	HMODULE handle;
	TCHAR	name[1];
};

extern "C"
	__declspec(dllimport)
	std::invoke_result_t<LPTHREAD_START_ROUTINE, GetRemoteModuleHandleMessage *>
		WINAPI
		get_remote_module_handle(GetRemoteModuleHandleMessage *msg);

void hook_attach(std::tstring_view dll, DWORD pid)
{
	ProcessHandle process(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
	if (!process.valid())
	{
		throw_last_error("OpenProcess"sv);
	}

	RemoteMemory remote_memory(process, (dll.length() + 1) * sizeof(TCHAR));
	remote_memory.write(dll.data());

	ThreadHandle remote_thread(
		CreateRemoteThread(
			process, nullptr, 0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibrary),
			remote_memory.get_address(), 0, nullptr));
	remote_thread.join();
}

void hook_detach(std::tstring_view hook_exe, std::tstring_view dll, DWORD pid)
{
	ProcessHandle process(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
	if (!process.valid())
	{
		throw_last_error("OpenProcess"sv);
	}

	ThreadHandle remote_thread;

	const auto	 hook_helper{ std::filesystem::absolute(hook_exe).replace_extension("dll").tstring() };
	RemoteMemory hook_helper_memory(process, std::max(sizeof(GetRemoteModuleHandleMessage), offsetof(GetRemoteModuleHandleMessage, name) + (hook_helper.length() + 1) * sizeof(TCHAR)));
	RemoteMemory dll_memory(process, std::max(sizeof(GetRemoteModuleHandleMessage), offsetof(GetRemoteModuleHandleMessage, name) + (dll.length() + 1) * sizeof(TCHAR)));
	hook_helper_memory.write(hook_helper.c_str(), offsetof(GetRemoteModuleHandleMessage, name), (hook_helper.length() + 1) * sizeof(TCHAR));
	dll_memory.write(dll.data(), offsetof(GetRemoteModuleHandleMessage, name), (dll.length() + 1) * sizeof(TCHAR));

	remote_thread = CreateRemoteThread(
		process, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibrary),
		hook_helper_memory.get_address(offsetof(GetRemoteModuleHandleMessage, name)), 0, nullptr);
	remote_thread.join();

	HMODULE hook_helper_handle, dll_handle;

	remote_thread = CreateRemoteThread(
		process, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(get_remote_module_handle),
		hook_helper_memory.get_address(), 0, nullptr);
	remote_thread.join();
	hook_helper_memory.read(&hook_helper_handle, offsetof(GetRemoteModuleHandleMessage, handle), sizeof(HMODULE));

	remote_thread = CreateRemoteThread(
		process, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(get_remote_module_handle),
		dll_memory.get_address(), 0, nullptr);
	remote_thread.join();
	dll_memory.read(&dll_handle, offsetof(GetRemoteModuleHandleMessage, handle), sizeof(HMODULE));

	if (dll_handle == nullptr)
	{
		tprintln(TEXT("[INFO] DLL '{}' is not loaded by process {}."), dll, pid);
	}
	else
	{
		remote_thread = CreateRemoteThread(
			process, nullptr, 0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(FreeLibrary),
			dll_handle, 0, nullptr);
		remote_thread.join();
	}

	remote_thread = CreateRemoteThread(
		process, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(FreeLibrary),
		hook_helper_handle, 0, nullptr);
	remote_thread.join();
}

void hook_exec(std::tstring_view dll, std::tstring_view command_line)
{
	STARTUPINFO			startup_info{ .cb = sizeof(STARTUPINFO) };
	PROCESS_INFORMATION process_info{};
	if (CreateProcess(
			nullptr, const_cast<LPTSTR>(command_line.data()),
			nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
			nullptr, nullptr,
			&startup_info, &process_info) == FALSE)
	{
		throw_last_error("CreateProcess"sv);
	}

	ProcessHandle process(process_info.hProcess);
	ThreadHandle  thread(process_info.hThread);
	if (!process.valid() || !thread.valid())
	{
		throw_last_error("CreateProcess"sv);
	}

	RemoteMemory remote_memory(process, (dll.length() + 1) * sizeof(TCHAR));
	remote_memory.write(dll.data());

	ThreadHandle remote_thread(
		CreateRemoteThread(
			process, nullptr, 0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibrary),
			remote_memory.get_address(), 0, nullptr));
	remote_thread.join();

	ResumeThread(thread);
}

int _tmain(int argc, TCHAR **argv)
try
{
	if (argc <= 3)
	{
		std::println("Usage:");
		tprintln(TEXT("(1) \"{}\" <dll> attach <pid>"), argv[0]);
		tprintln(TEXT("(2) \"{}\" <dll> detach <pid>"), argv[0]);
		tprintln(TEXT("(3) \"{}\" <dll> exec <command> [<args>...]"), argv[0]);
		return 0;
	}

	std::tstring_view operation{ argv[2] };
	if (operation == TEXT("attach"sv))
	{
		hook_attach(argv[1], std::stoul(argv[3]));
	}
	else if (operation == TEXT("detach"sv))
	{
		hook_detach(argv[0], argv[1], std::stoul(argv[3]));
	}
	else if (operation == TEXT("exec"sv))
	{
		std::tstring command_line(GetCommandLine());

		auto iter{ command_line.begin() };
		for (int i{}; i < 3; ++i)
		{
			LPTSTR arg{ argv[i] };
			while (*arg != TEXT('\0'))
			{
				while (*iter != *arg)
				{
					++iter;
				}
				++iter;
				++arg;
			}
			iter = std::find_if(iter, command_line.end(), ::isspace);
			iter = std::find_if_not(iter, command_line.end(), ::isspace);
		}

		hook_exec(argv[1], { iter, command_line.end() });
	}
	return 0;
}
catch (const std::exception &e)
{
	std::println(stderr, "[Error] {}", e.what());
}
