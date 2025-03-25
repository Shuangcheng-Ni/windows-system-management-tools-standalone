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

#include <print>
#include <string>

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

inline void throw_last_error(std::string_view msg)
{
	throw std::runtime_error(std::format("{}: {:#010x}", msg, GetLastError()));
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

class LibraryLoader : public Guard<HMODULE, FreeLibrary> {
public:
	LibraryLoader(std::tstring_view path, DWORD flags = 0)
		: Guard(LoadLibraryEx(path.data(), nullptr, flags))
	{
		if (!valid())
		{
			throw_last_error("LoadLibraryEx"sv);
		}
	}

	auto name() const
	{
		std::tstring name;
		for (DWORD len{ MAX_PATH };; len *= 2)
		{
			name.resize(len);
			len = GetModuleFileName(*this, name.data(), len);
			if (len != 0)
			{
				switch (GetLastError())
				{
					case ERROR_SUCCESS:
						name.resize(len);
						return name;
					case ERROR_INSUFFICIENT_BUFFER:
						continue;
					default:
						break;
				}
			}
			throw_last_error("GetModuleFileName"sv);
		}
	}

	bool is_data_file() const noexcept
	{
		return (reinterpret_cast<ULONG_PTR>(SmartPtr::get()) & 1) != 0;
	}

	bool is_image_mapping() const noexcept
	{
		return (reinterpret_cast<ULONG_PTR>(SmartPtr::get()) & 2) != 0;
	}

	bool is_resource() const noexcept
	{
		return is_data_file() || is_image_mapping();
	}
};

class NTErrorMessage : public Guard<LPTSTR, LocalFree> {
public:
	NTErrorMessage(DWORD ec)
	{
		static LibraryLoader ntdll(TEXT("ntdll.dll"), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
		if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
						  ntdll, ec, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
						  reinterpret_cast<LPTSTR>((LPTSTR *)(&*this)), 0, nullptr) == 0)
		{
			throw_last_error("FormatMessage"sv);
		}
	}

	explicit operator std::tstring_view() const noexcept
	{
		return std::tstring_view(*this, std::max(LocalSize(*this) / sizeof(TCHAR), 1ZU) - 1);
	}
};

int _tmain(int argc, TCHAR **argv)
{
	if (argc < 2)
	{
		tprintln(TEXT("Usage: \"{}\" <error code>"), argv[0]);
		std::println("Error code: <dec>|0x<hex>|0<oct>");
		return 0;
	}

	try
	{
		auto ec{ std::stoll(argv[1], nullptr, 0) };
		std::println("error code: {0} | {1} | {1:#010x} | {1:#o}", static_cast<int>(ec), static_cast<DWORD>(ec));

		std::println("generic : {:?}", std::generic_category().message(static_cast<int>(ec)));
		std::println("system  : {:?}", std::system_category().message(static_cast<int>(ec)));

		NTErrorMessage msg(static_cast<DWORD>(ec));
		tprintln(TEXT("NTSTATUS: {:?}"), std::tstring_view(msg));
	}
	catch (const std::exception &e)
	{
		std::println(stderr, "[Error] {}", e.what());
	}
	return 0;
}
