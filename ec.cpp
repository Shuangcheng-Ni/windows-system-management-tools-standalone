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

#include <Windows.h>
#include <tchar.h>

using namespace std::literals;

namespace stdext {
template <class... Ts>
inline void wprint(const ::std::wformat_string<Ts...> fmt, Ts &&...args)
{
	auto cp{ GetConsoleOutputCP() };
	auto wstr{ ::std::format(fmt, ::std::forward<decltype(args)>(args)...) };
	auto len{ WideCharToMultiByte(cp, 0, wstr.data(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, nullptr) };

	::std::string str(len, '\0');
	WideCharToMultiByte(cp, 0, wstr.data(), static_cast<int>(wstr.length()), str.data(), len, nullptr, nullptr);
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

template <class T, auto CleanUp, auto InvalidValue = T{}, bool UseCApi = true>
	requires(std::is_trivially_copy_constructible_v<T> && std::is_trivially_copy_assignable_v<T>) &&
			((std::invocable<decltype(CleanUp), T> && (UseCApi || noexcept(CleanUp(std::declval<T>())))) ||
			 (std::invocable<decltype(CleanUp), T *> && (UseCApi || noexcept(CleanUp(std::declval<T *>())))))
class Guard {
protected:
	inline static const T invalid_value = [] {
		if constexpr (std::convertible_to<decltype(InvalidValue), T>)
		{
			return static_cast<T>(InvalidValue);
		}
		else
		{
			return reinterpret_cast<T>(InvalidValue);
		}
	}();

	T value{ invalid_value };

public:
	Guard() noexcept = default;
	Guard(Guard &&other) noexcept
		: value{ std::exchange(other.value, invalid_value) } {}
	explicit Guard(T &&v) noexcept
		: value{ v } {}

	~Guard()
	{
		if (!valid())
		{
			return;
		}
		if constexpr (std::invocable<decltype(CleanUp), T>)
		{
			CleanUp(value);
		}
		else
		{
			CleanUp(&value);
		}
	}

	Guard &operator=(Guard &&other) noexcept
	{
		if (this != std::addressof(other))
		{
			this->~Guard();
			new (this) Guard(std::move(other));
		}
		return *this;
	}
	Guard &operator=(T &&v) noexcept
	{
		this->~Guard();
		new (this) Guard(std::move(v));
		return *this;
	}

	operator T() const noexcept { return value; }

	T *operator&() noexcept { return &value; }

	auto operator->() noexcept
	{
		if constexpr (std::is_pointer_v<T>)
		{
			return value;
		}
		else
		{
			return &value;
		}
	}

	bool valid() const noexcept
	{
		if constexpr (std::equality_comparable<T>)
		{
			return value != invalid_value;
		}
		else
		{
			return std::memcmp(&value, &invalid_value, sizeof(T)) != 0;
		}
	}
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
			len = GetModuleFileName(value, name.data(), len);
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
		return (reinterpret_cast<ULONG_PTR>(value) & 1) != 0;
	}

	bool is_image_mapping() const noexcept
	{
		return (reinterpret_cast<ULONG_PTR>(value) & 2) != 0;
	}

	bool is_resource() const noexcept
	{
		return is_data_file() || is_image_mapping();
	}
};

class Win32ErrorMessage : public Guard<LPTSTR, LocalFree> {
private:
	DWORD len{};

public:
	Win32ErrorMessage(DWORD ec)
	{
		static LibraryLoader ntdll(TEXT("ntdll.dll"), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
		len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
							ntdll, ec, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
							reinterpret_cast<LPTSTR>(&value), 0, nullptr);
		if (len == 0)
		{
			throw_last_error("FormatMessage"sv);
		}
	}

	explicit operator std::tstring_view() const noexcept { return std::tstring_view(value, len); }
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

		std::println("generic : {}", std::generic_category().message(static_cast<int>(ec)));
		std::println("system  : {}", std::system_category().message(static_cast<int>(ec)));

		Win32ErrorMessage msg(static_cast<DWORD>(ec));
		tprintln(TEXT("NTSTATUS: {}"), std::tstring_view(msg));
	}
	catch (const std::exception &e)
	{
		std::println(stderr, "[Error] {}", e.what());
	}
	return 0;
}
