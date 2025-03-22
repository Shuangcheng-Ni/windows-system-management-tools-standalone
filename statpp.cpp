#include <chrono>
#include <filesystem>
#include <print>
#include <ranges>
#include <spanstream>
#include <unordered_map>
#include <vector>

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

template <bool IsConst = false>
class FileAttrs {
private:
	using Rep = decltype(FILE_BASIC_INFORMATION::FileAttributes);

	std::conditional_t<IsConst, const Rep &, Rep &> &attrs;

	friend struct std::formatter<FileAttrs>;

public:
#pragma push_macro("FILE_ATTR")
#undef FILE_ATTR
#define FILE_ATTR(attr) std::make_pair(#attr##sv, FILE_ATTRIBUTE_##attr)
	inline static const std::unordered_map attrs_table{
		FILE_ATTR(READONLY),
		FILE_ATTR(HIDDEN),
		FILE_ATTR(SYSTEM),
		FILE_ATTR(DIRECTORY),
		FILE_ATTR(ARCHIVE),
		FILE_ATTR(DEVICE),
		FILE_ATTR(NORMAL),
		FILE_ATTR(TEMPORARY),
		FILE_ATTR(SPARSE_FILE),
		FILE_ATTR(REPARSE_POINT),
		FILE_ATTR(COMPRESSED),
		FILE_ATTR(OFFLINE),
		FILE_ATTR(NOT_CONTENT_INDEXED),
		FILE_ATTR(ENCRYPTED),
		FILE_ATTR(INTEGRITY_STREAM),
		FILE_ATTR(VIRTUAL),
		FILE_ATTR(NO_SCRUB_DATA),
		FILE_ATTR(EA),
		FILE_ATTR(PINNED),
		FILE_ATTR(UNPINNED),
		FILE_ATTR(RECALL_ON_OPEN),
		FILE_ATTR(RECALL_ON_DATA_ACCESS)
	};
#undef FILE_ATTR
#pragma pop_macro("FILE_ATTR")

	explicit constexpr FileAttrs(std::conditional_t<IsConst, const FILE_BASIC_INFORMATION &, FILE_BASIC_INFORMATION &> file_info) noexcept
		: attrs(file_info.FileAttributes) {}

	void update(std::string_view cmd)
	{
#pragma warning(push)
#pragma warning(disable : 4244)
		std::string cmd_str(std::from_range, cmd | std::views::transform(::toupper));
#pragma warning(pop)
		for (const auto &op : cmd_str | std::views::split(','))
		{
			std::string_view op_str(op | std::views::drop_while(::isspace));
			if (op_str.length() <= 1 || (op_str[0] != '+' && op_str[0] != '-'))
			{
				continue;
			}

			auto iter{ attrs_table.find(op_str.substr(1)) };
			if (iter == attrs_table.end())
			{
				continue;
			}

			switch (op_str[0])
			{
				case '+':
					attrs |= iter->second;
					break;
				case '-':
					attrs &= ~iter->second;
					break;
			}
		}
	}
};

template <class T>
FileAttrs(T &) -> FileAttrs<std::is_const_v<T>>;

template <bool IsConst>
struct std::formatter<FileAttrs<IsConst>> : std::formatter<std::vector<string_view>> {
	template <class FormatContext>
	auto format(const FileAttrs<IsConst> &file_attrs, FormatContext &ctx) const
	{
		std::vector<std::string_view> attr_names;
		for (const auto &[attr_name, attr_rep] : FileAttrs<IsConst>::attrs_table)
		{
			if ((file_attrs.attrs & attr_rep) != 0)
			{
				attr_names.emplace_back(attr_name);
			}
		}
		return std::formatter<std::vector<std::string_view>>::format(attr_names, ctx);
	}
};

template <>
struct std::formatter<FILE_BASIC_INFORMATION> : std::formatter<std::string> {
	using Base = std::formatter<std::string>;

	template <class FormatContext>
	auto format(const FILE_BASIC_INFORMATION &file_info, FormatContext &ctx) const
	{
		Base::format(std::format("attrs : {}\n", FileAttrs(file_info)), ctx);
		Base::format(std::format("atime : {}\n", FileTime(file_info.LastAccessTime)), ctx);
		Base::format(std::format("mtime : {}\n", FileTime(file_info.LastWriteTime)), ctx);
		Base::format(std::format("ctime : {}\n", FileTime(file_info.ChangeTime)), ctx);
		Base::format(std::format("crtime: {}\n", FileTime(file_info.CreationTime)), ctx);
		return ctx.out();
	}
};

class FileStatus {
private:
	Handle				   hdl;
	IO_STATUS_BLOCK		   io_stat;
	FILE_BASIC_INFORMATION file_info;

public:
	FileStatus(std::string_view path, ACCESS_MASK access)
	{
		std::string obj_name;
		if (path.starts_with("\\Device\\"sv) ||
			path.starts_with("\\DosDevices\\"sv) ||
			path.starts_with("\\Global??\\"sv) || path.starts_with("\\??\\"sv))
		{
			obj_name = path;
		}
		else if (path.starts_with("\\\\?\\"sv) || path.starts_with("\\\\.\\"sv))
		{
			obj_name = std::format("\\??\\{}", path.substr(4));
		}
		else if (path.starts_with("\\\\"sv))
		{
			obj_name = std::format("\\??\\UNC\\{}", path.substr(2));
		}
		else
		{
			obj_name = std::format("\\??\\{}", std::filesystem::absolute(path).string());
		}
		std::println("{}", obj_name);

		ANSI_STRING ansi_str{
			.Length		   = static_cast<decltype(ANSI_STRING::Length)>(obj_name.length()),
			.MaximumLength = static_cast<decltype(ANSI_STRING::MaximumLength)>(obj_name.capacity()),
			.Buffer		   = obj_name.data()
		};
		UnicodeString uc_str;
		uc_str.stat = RtlAnsiStringToUnicodeString(&uc_str, &ansi_str, true);
		check_ntstatus(uc_str.stat, "RtlAnsiStringToUnicodeString"sv);

		OBJECT_ATTRIBUTES obj_attrs;
		InitializeObjectAttributes(&obj_attrs, &uc_str, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		hdl.stat = ZwOpenFile(&hdl, access, &obj_attrs, &io_stat, 0,
							  FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT);
		check_ntstatus(hdl.stat, "ZwOpenFile"sv);
	}

	bool is_open() const noexcept { return hdl.valid(); }

	[[nodiscard]] const FILE_BASIC_INFORMATION &query()
	{
		auto stat{ ZwQueryInformationFile(hdl, &io_stat, &file_info, sizeof(file_info), FileBasicInformation) };
		check_ntstatus(stat, "ZwQueryInformationFile"sv);
		return file_info;
	}

	void update(std::string_view field, std::string_view value)
	{
		bool valid{ false };

		if (field == "attrs"sv)
		{
			FileAttrs(file_info).update(value);
			valid = true;
		}
		else if (field == "atime"sv)
		{
			valid = FileTime(file_info.LastAccessTime).update(value);
		}
		else if (field == "mtime"sv)
		{
			valid = FileTime(file_info.LastWriteTime).update(value);
		}
		else if (field == "ctime"sv)
		{
			valid = FileTime(file_info.ChangeTime).update(value);
		}
		else if (field == "crtime"sv)
		{
			valid = FileTime(file_info.CreationTime).update(value);
		}

		if (!valid)
		{
			throw std::invalid_argument(std::format("Invalid arguments: `{}' and `{}'", field, value));
		}

		auto stat{ ZwSetInformationFile(hdl, &io_stat, &file_info, sizeof(file_info), FileBasicInformation) };
		check_ntstatus(stat, "ZwSetInformationFile"sv);
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
	if (argc != 2 && argc != 4)
	{
		std::println("Usage: \"{}\" <file> [<field> <value>]", argv[0]);
		std::println("field: attrs, atime, mtime, ctime, crtime");
		std::println("attrs: \"+attr1,-attr2,...\" {}", FileAttrs<>::attrs_table | std::views::keys);
		std::println("time : \"%F %T %z\" (yyyy-mm-dd HH:MM:SS.SSSSSSS ±zzzz)");
		return 0;
	}

	try
	{
		acquire_privileges();

		ACCESS_MASK access{ FILE_READ_ATTRIBUTES };
		if (argc == 4)
		{
			access |= FILE_WRITE_ATTRIBUTES;
		}

		FileStatus file_status(argv[1], access);
		std::println("{}", file_status.query());
		if (argc == 4)
		{
			file_status.update(argv[2], argv[3]);
			std::println("New status:");
			std::println("{}", file_status.query());
		}
	}
	catch (const std::exception &e)
	{
		std::println(stderr, "[Error] {}", e.what());
	}
	return 0;
}
