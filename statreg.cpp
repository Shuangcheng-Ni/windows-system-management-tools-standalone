#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <print>
#include <ranges>
#include <spanstream>

#if defined(_M_AMD64) || defined(_M_X64)
#pragma message("Target: x64")
#define _AMD64_
#elif defined(_M_IX86)
#pragma message("Target: x86")
#define _X86_
#endif
#include <ntifs.h>
// /I "%WindowsSDKDir%Include\%WindowsSDKVersion%km"
// /link ntdll.lib

using namespace std::literals;

inline void check_ntstatus(NTSTATUS stat, std::string_view msg)
{
	if (stat != STATUS_SUCCESS)
	{
		throw std::runtime_error(std::format("{}: {:#010x}", msg, static_cast<std::make_unsigned_t<NTSTATUS>>(stat)));
	}
}

template <class T, auto CleanUp, bool UseCApi = true>
	requires(std::is_trivially_default_constructible_v<T>) &&
			((std::invocable<decltype(CleanUp), T> && (UseCApi || noexcept(CleanUp(std::declval<T>())))) ||
			 (std::invocable<decltype(CleanUp), T *> && (UseCApi || noexcept(CleanUp(std::declval<T *>())))))
class Guard {
protected:
	T value;

public:
	NTSTATUS stat{ ~STATUS_SUCCESS };

	Guard() noexcept = default;

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

	Guard(const Guard &)			= delete;
	Guard(Guard &&)					= delete;
	Guard &operator=(const Guard &) = delete;
	Guard &operator=(Guard &&)		= delete;

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

	bool valid() const noexcept { return stat == STATUS_SUCCESS; }
};

using Handle		= Guard<HANDLE, ZwClose>;
using AnsiString	= Guard<ANSI_STRING, RtlFreeAnsiString>;
using UnicodeString = Guard<UNICODE_STRING, RtlFreeUnicodeString>;

template <bool IsConst = false>
class FileTime {
private:
	using Rep = decltype(LARGE_INTEGER::QuadPart);

	std::conditional_t<IsConst, const Rep &, Rep &> time_ticks;

public:
	using TimePoint = std::filesystem::file_time_type;

	explicit constexpr FileTime(std::conditional_t<IsConst, const LARGE_INTEGER &, LARGE_INTEGER &> file_time) noexcept
		: time_ticks(file_time.QuadPart) {}

	explicit constexpr operator TimePoint() const
	{
		return TimePoint(TimePoint::duration(time_ticks));
	}

	bool update(std::string_view date_string, std::string_view fmt = "%F %T %z"sv)
	{
		TimePoint		 tp;
		std::ispanstream iss(date_string);
		std::chrono::from_stream(iss, fmt.data(), tp);
		if (iss.fail())
		{
			return false;
		}
		time_ticks = tp.time_since_epoch().count();
		return true;
	}
};

template <class T>
FileTime(T &) -> FileTime<std::is_const_v<T>>;

template <bool IsConst>
struct std::formatter<FileTime<IsConst>> : std::formatter<std::string> {
	template <class FormatContext>
	auto format(const FileTime<IsConst> &file_time, FormatContext &ctx) const
	{
		return std::formatter<std::string>::format(
			std::format("{:%F %T %z (%Z)}",
						std::chrono::zoned_time(std::chrono::current_zone(),
												clock_cast<std::chrono::system_clock>(FileTime<IsConst>::TimePoint(file_time)))),
			ctx);
	}
};

template <>
struct std::formatter<KEY_BASIC_INFORMATION> : std::formatter<std::string> {
	using Base = std::formatter<std::string>;

	template <class FormatContext>
	auto format(const KEY_BASIC_INFORMATION &key_info, FormatContext &ctx) const
	{
		UNICODE_STRING uc_str{
			.Length		   = static_cast<decltype(UNICODE_STRING::Length)>(key_info.NameLength),
			.MaximumLength = static_cast<decltype(UNICODE_STRING::MaximumLength)>(key_info.NameLength),
			.Buffer		   = const_cast<decltype(UNICODE_STRING::Buffer)>(key_info.Name)
		};
		AnsiString ansi_str;
		ansi_str.stat = RtlUnicodeStringToAnsiString(&ansi_str, &uc_str, true);
		check_ntstatus(ansi_str.stat, "RtlUnicodeStringToAnsiString"sv);

		Base::format(std::format("LastWriteTime: {}\n", FileTime(key_info.LastWriteTime)), ctx);
		Base::format(std::format("TitleIndex   : {}\n", key_info.TitleIndex), ctx);
		Base::format(std::format("NameLength   : {}\n", key_info.NameLength), ctx);
		Base::format(std::format("Name         : {:.{}}\n", ansi_str->Buffer, ansi_str->Length), ctx);
		return ctx.out();
	}
};

inline auto get_current_user_sid()
{
	Handle	 hdl;
	NTSTATUS stat;

	hdl.stat = ZwOpenProcessTokenEx(ZwCurrentProcess(), TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hdl);
	check_ntstatus(hdl.stat, "ZwOpenProcessTokenEx"sv);

	ULONG len;
	stat = ZwQueryInformationToken(hdl, TokenUser, nullptr, 0, &len);
	if (stat != STATUS_BUFFER_TOO_SMALL)
	{
		check_ntstatus(stat, "ZwQueryInformationToken"sv);
	}

	std::string sid_buf(len, '\0');
	stat = ZwQueryInformationToken(hdl, TokenUser, sid_buf.data(), len, &len);
	check_ntstatus(stat, "ZwQueryInformationToken"sv);
	auto sid_ptr{ reinterpret_cast<PTOKEN_USER>(sid_buf.data())->User.Sid };

	UnicodeString uc_str;
	uc_str.stat = RtlConvertSidToUnicodeString(&uc_str, sid_ptr, true);
	check_ntstatus(stat, "RtlConvertSidToUnicodeString"sv);

	AnsiString ansi_str;
	ansi_str.stat = RtlUnicodeStringToAnsiString(&ansi_str, &uc_str, true);
	check_ntstatus(stat, "RtlUnicodeStringToAnsiString"sv);
	return std::string(ansi_str->Buffer, ansi_str->Length);
}

class RegStatus {
private:
	Handle		hdl;
	std::string key_info_buf;

	static std::optional<std::string> get_obj_name(std::string_view path, std::string_view new_prefix, const std::string_view (&prefixes)[4])
	{
		for (const auto &prefix : prefixes)
		{
			if (path.starts_with(prefix))
			{
				return std::format("\\Registry\\{}\\{}", new_prefix, path.substr(prefix.length()));
			}
		}
		return std::nullopt;
	}

	bool try_open(std::string_view obj_name, ACCESS_MASK access)
	{
		ANSI_STRING ansi_str{
			.Length		   = static_cast<decltype(ANSI_STRING::Length)>(obj_name.length()),
			.MaximumLength = static_cast<decltype(ANSI_STRING::MaximumLength)>(obj_name.length()),
			.Buffer		   = const_cast<decltype(ANSI_STRING::Buffer)>(obj_name.data())
		};
		UnicodeString uc_str;
		uc_str.stat = RtlAnsiStringToUnicodeString(&uc_str, &ansi_str, true);
		check_ntstatus(uc_str.stat, "RtlAnsiStringToUnicodeString"sv);

		OBJECT_ATTRIBUTES obj_attrs;
		InitializeObjectAttributes(&obj_attrs, &uc_str, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, nullptr, nullptr);

		hdl.stat = ZwOpenKeyEx(&hdl, access, &obj_attrs,
							   REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK);
		if (is_open())
		{
			std::println("{}", obj_name);
			return true;
		}
		return false;
	}

	auto key_info() noexcept
	{
		return reinterpret_cast<PKEY_BASIC_INFORMATION>(key_info_buf.data());
	}

public:
	RegStatus(std::string_view path, ACCESS_MASK access)
	{
		if (path.starts_with("\\Registry\\"sv))
		{
			try_open(path, access);
			check_ntstatus(hdl.stat, "ZwOpenKeyEx"sv);
			return;
		}

		const auto		 current_user_sid{ get_current_user_sid() };
		const std::array new_prefixes{
			std::format("User\\{}\\Software\\Classes", current_user_sid),
			"Machine\\Software\\Classes"s,
			std::format("User\\{}", current_user_sid),
			"Machine"s,
			"Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current"s,
			"User"s
		};
		constexpr static std::string_view prefix_groups[][4]{
			{ "HKCR\\", "HKCR:\\", "HKEY_CLASSES_ROOT\\", "Registry::HKEY_CLASSES_ROOT\\" },
			{ "HKCR\\", "HKCR:\\", "HKEY_CLASSES_ROOT\\", "Registry::HKEY_CLASSES_ROOT\\" },
			{ "HKCU\\", "HKCU:\\", "HKEY_CURRENT_USER\\", "Registry::HKEY_CURRENT_USER\\" },
			{ "HKLM\\", "HKLM:\\", "HKEY_LOCAL_MACHINE\\", "Registry::HKEY_LOCAL_MACHINE\\" },
			{ "HKCC\\", "HKCC:\\", "HKEY_CURRENT_CONFIG\\", "Registry::HKEY_CURRENT_CONFIG\\" },
			{ "HKU\\", "HKU:\\", "HKEY_USERS\\", "Registry::HKEY_USERS\\" }
		};

		for (const auto &[new_prefix, prefixes] : std::views::zip(new_prefixes, prefix_groups))
		{
			auto obj_name{ get_obj_name(path, new_prefix, prefixes) };
			if (obj_name != std::nullopt && try_open(*obj_name, access))
			{
				return;
			}
		}
		check_ntstatus(hdl.stat, "ZwOpenKeyEx"sv);
	}

	bool is_open() const noexcept { return hdl.valid(); }

	[[nodiscard]] const KEY_BASIC_INFORMATION &query()
	{
		NTSTATUS stat;

		ULONG len;
		stat = ZwQueryKey(hdl, KeyBasicInformation, nullptr, 0, &len);
		if (stat != STATUS_BUFFER_TOO_SMALL)
		{
			check_ntstatus(stat, "ZwQueryKey"sv);
		}
		key_info_buf.resize(len);

		stat = ZwQueryKey(hdl, KeyBasicInformation, key_info(), len, &len);
		check_ntstatus(stat, "ZwQueryKey"sv);
		return *key_info();
	}

	void update(std::string_view field, std::string_view value)
	{
		bool valid{ false };

		if (field == "mtime"sv)
		{
			valid = FileTime(key_info()->LastWriteTime).update(value);
		}

		if (!valid)
		{
			throw std::invalid_argument(std::format("Invalid arguments: `{}' and `{}'", field, value));
		}

		auto stat{ ZwSetInformationKey(hdl, KeyWriteTimeInformation, key_info(), sizeof(KEY_WRITE_TIME_INFORMATION)) };
		check_ntstatus(stat, "ZwSetInformationKey"sv);
	}

	void remove()
	{
		auto stat{ ZwDeleteKey(hdl) };
		check_ntstatus(stat, "ZwDeleteKey"sv);
	}
};

inline void acquire_privileges()
{
	Handle	 hdl;
	NTSTATUS stat;

	hdl.stat = ZwOpenProcessTokenEx(ZwCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
									OBJ_KERNEL_HANDLE, &hdl);
	check_ntstatus(hdl.stat, "ZwOpenProcessTokenEx"sv);

	ULONG len;
	stat = ZwQueryInformationToken(hdl, TokenPrivileges, nullptr, 0, &len);
	if (stat != STATUS_BUFFER_TOO_SMALL)
	{
		check_ntstatus(stat, "ZwQueryInformationToken"sv);
	}

	std::string buf(len, '\0');
	stat = ZwQueryInformationToken(hdl, TokenPrivileges, buf.data(), len, &len);
	check_ntstatus(stat, "ZwQueryInformationToken"sv);

	auto tp{ reinterpret_cast<PTOKEN_PRIVILEGES>(buf.data()) };
	for (ULONG i{}; i < tp->PrivilegeCount; ++i)
	{
		tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
	}

	stat = NtAdjustPrivilegesToken(hdl, FALSE, tp, len, nullptr, nullptr);
	check_ntstatus(stat, "NtAdjustPrivilegesToken"sv);
}

int main(int argc, char **argv)
{
	if (argc != 2 && !(argc == 3 && argv[2] == "delete"sv) && argc != 4)
	{
		std::println("Usage: \"{}\" <registry> [<field> <value>]|[delete]", argv[0]);
		std::println("field: mtime");
		std::println("time : \"%F %T %z\" (yyyy-mm-dd HH:MM:SS.SSSSSSS ±zzzz)");
		return 0;
	}

	try
	{
		acquire_privileges();

		ACCESS_MASK access{ KEY_READ };
		switch (argc)
		{
			case 3:
				access |= DELETE;
				break;
			case 4:
				access |= KEY_WRITE;
				break;
			default:
				break;
		}

		RegStatus reg_status(argv[1], access);
		std::println("{}", reg_status.query());
		if (argc == 3)
		{
			reg_status.remove();
		}
		else if (argc == 4)
		{
			reg_status.update(argv[2], argv[3]);
			std::println("New status:");
			std::println("{}", reg_status.query());
		}
	}
	catch (const std::exception &e)
	{
		std::println(stderr, "[Error] {}", e.what());
	}
	return 0;
}
