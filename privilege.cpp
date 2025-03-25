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

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <print>
#include <ranges>
#include <vector>

#define NOMINMAX
#include <AclAPI.h>
#include <sddl.h>
#include <tchar.h>

using namespace std::literals;

template <class T>
concept ByteContainer = std::ranges::input_range<T> &&
						std::same_as<std::ranges::range_value_t<T>, BYTE>;

template <ByteContainer R>
	requires std::same_as<R, std::remove_cvref_t<R>>
inline constexpr auto std::format_kind<R> = std::range_format::disabled;

template <ByteContainer R, class CharT>
struct std::formatter<R, CharT> : std::range_formatter<BYTE, CharT> {
	constexpr static CharT separator[]{ 32, 0 };

	constexpr formatter() noexcept { this->set_separator(separator); }
};

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

using Handle			 = Guard<HANDLE, CloseHandle, -1Z>; // -1Z: INVALID_HANDLE_VALUE
using String			 = Guard<LPTSTR, LocalFree>;
using SecurityDescriptor = Guard<PSECURITY_DESCRIPTOR, LocalFree>;

class HKey : public Guard<HKEY, RegCloseKey> {
private:
	inline static const std::array key_roots{ HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS };

	constexpr static std::tstring_view prefix_groups[][4]{
		{ TEXT("HKCR\\"), TEXT("HKCR:\\"), TEXT("HKEY_CLASSES_ROOT\\"), TEXT("Registry::HKEY_CLASSES_ROOT\\") },
		{ TEXT("HKCU\\"), TEXT("HKCU:\\"), TEXT("HKEY_CURRENT_USER\\"), TEXT("Registry::HKEY_CURRENT_USER\\") },
		{ TEXT("HKLM\\"), TEXT("HKLM:\\"), TEXT("HKEY_LOCAL_MACHINE\\"), TEXT("Registry::HKEY_LOCAL_MACHINE\\") },
		{ TEXT("HKU\\"), TEXT("HKU:\\"), TEXT("HKEY_USERS\\"), TEXT("Registry::HKEY_USERS\\") }
	};

public:
	static auto reg_split(std::tstring_view path)
	{
		for (const auto &[key_root, prefixes] : std::views::zip(key_roots, prefix_groups))
		{
			for (const auto &prefix : prefixes)
			{
				if (path.starts_with(prefix))
				{
					return std::make_pair(key_root, path.data() + prefix.length());
				}
			}
		}
		throw std::invalid_argument("Invalid registry path.");
	}

	HKey(std::tstring_view path, DWORD options, REGSAM sam_desired)
	{
		auto [key_root, sub_key] = reg_split(path);
		if (auto ec{ RegOpenKeyEx(key_root, sub_key, options, sam_desired, &*this) };
			ec != ERROR_SUCCESS)
		{
			SetLastError(ec);
			throw_last_error("RegOpenKeyEx"sv);
		}
	}

	HKey(std::tstring_view path, DWORD open_options, DWORD create_options, REGSAM sam_desired)
	{
		auto [key_root, sub_key] = reg_split(path);
		LSTATUS ec;
		bool	exists{ true };
		ec = RegOpenKeyEx(key_root, sub_key, open_options, sam_desired, &*this);
		if (ec == ERROR_FILE_NOT_FOUND)
		{
			std::println(stderr, "[INFO] Registry key not found. Trying to create one.");
			ec	   = RegCreateKeyEx(key_root, sub_key, 0, nullptr, create_options,
									sam_desired, nullptr, &*this, nullptr);
			exists = false;
		}
		if (ec != ERROR_SUCCESS)
		{
			SetLastError(ec);
			throw_last_error(exists ? "RegOpenKeyEx"sv : "RegCreateKeyEx"sv);
		}
	}
};

inline void acquire_privileges()
{
	Handle hdl;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hdl) == FALSE)
	{
		throw_last_error("OpenProcessToken"sv);
	}

	DWORD len;
	GetTokenInformation(hdl, TokenPrivileges, nullptr, 0, &len);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		throw_last_error("GetTokenInformation"sv);
	}

	std::string buf(len, '\0');
	if (GetTokenInformation(hdl, TokenPrivileges, buf.data(), len, &len) == FALSE)
	{
		throw_last_error("GetTokenInformation"sv);
	}
	auto tp{ reinterpret_cast<PTOKEN_PRIVILEGES>(buf.data()) };

	std::vector<std::pair<std::tstring, DWORD>> privileges;
	for (DWORD i{}; i < tp->PrivilegeCount; ++i)
	{
		auto &priv{ tp->Privileges[i] };
		DWORD name_len{};
		LookupPrivilegeName(nullptr, &priv.Luid, nullptr, &name_len);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			throw_last_error("LookupPrivilegeName"sv);
		}

		std::tstring name(name_len - 1, TEXT('\0'));
		if (LookupPrivilegeName(nullptr, &priv.Luid, name.data(), &name_len) == FALSE)
		{
			throw_last_error("LookupPrivilegeName"sv);
		}
		privileges.emplace_back(std::move(name), priv.Attributes);
		priv.Attributes = SE_PRIVILEGE_ENABLED;
	}
	auto max_width{ privileges.size() == 0 ? 0 : std::ranges::max(privileges | std::views::keys | std::views::transform(&std::tstring::length)) };

	std::println("Current privileges:");
	for (const auto &[name, attr] : privileges)
	{
		tprintln(TEXT("{:{}}: {:#010x}"), name, max_width, attr);
	}
	std::println();

	std::println("Enabling privileges...");
	if (AdjustTokenPrivileges(hdl, FALSE, tp, len, nullptr, nullptr) == FALSE)
	{
		throw_last_error("AdjustTokenPrivileges"sv);
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		throw_last_error("AdjustTokenPrivileges"sv);
	}
	std::println();

	if (GetTokenInformation(hdl, TokenPrivileges, buf.data(), len, &len) == FALSE)
	{
		throw_last_error("GetTokenInformation"sv);
	}
	for (DWORD i{}; i < tp->PrivilegeCount; ++i)
	{
		privileges[i].second = tp->Privileges[i].Attributes;
	}

	std::println("Current privileges:");
	for (const auto &[name, attr] : privileges)
	{
		tprintln(TEXT("{:{}}: {:#010x}"), name, max_width, attr);
	}
	std::println();
}

void priv_read(const std::filesystem::path &infile, const std::filesystem::path &outfile)
{
	Handle hdl(CreateFile(infile.tstring().c_str(), GENERIC_READ, 0,
						  nullptr, OPEN_EXISTING,
						  FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!hdl.valid())
	{
		throw_last_error("CreateFile"sv);
	}

	LARGE_INTEGER file_size;
	if (GetFileSizeEx(hdl, &file_size) == FALSE)
	{
		throw_last_error("GetFileSizeEx"sv);
	}
	auto len{ file_size.LowPart };

	std::string buf(len, '\0');
	if (ReadFile(hdl, buf.data(), len, &len, nullptr) == FALSE)
	{
		throw_last_error("ReadFile"sv);
	}

	std::ofstream fout(outfile, std::ios::binary | std::ios::noreplace);
	if (!fout.is_open())
	{
		throw_last_error("std::ofstream"sv);
	}
	fout.write(buf.data(), len);
}

void priv_write(const std::filesystem::path &infile, const std::filesystem::path &outfile)
{
	Handle hdl(CreateFile(outfile.tstring().c_str(), GENERIC_WRITE, 0,
						  nullptr, CREATE_ALWAYS,
						  FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!hdl.valid())
	{
		throw_last_error("CreateFile"sv);
	}

	std::ifstream fin(infile, std::ios::binary);
	if (!fin.is_open())
	{
		throw_last_error("std::ifstream"sv);
	}

	std::string buf(std::istreambuf_iterator(fin), {});
	if (WriteFile(hdl, buf.data(), static_cast<DWORD>(buf.length()), nullptr, nullptr) == FALSE)
	{
		throw_last_error("WriteFile"sv);
	}
}

void priv_list(const std::filesystem::path &path)
{
	using FileInfo = std::tuple<std::string, std::string, std::string, std::string, std::string>;

	std::vector<FileInfo> file_infos;

	for (const auto &entry : std::filesystem::directory_iterator(path))
	{
		std::error_code _;
		file_infos.emplace_back(
			std::string(10, '\0'),
			std::to_string(entry.hard_link_count(_)),
			std::to_string(entry.file_size(_)),
			std::format("{:%FT%T%z}",
						std::chrono::zoned_time(std::chrono::current_zone(),
												clock_cast<std::chrono::system_clock>(entry.last_write_time(_)))),
			entry.path().filename().string());

		auto stat{ entry.symlink_status() };
		auto iter{ std::get<0>(file_infos.back()).begin() };

		switch (stat.type())
		{
			using enum std::filesystem::file_type;
			case directory:
				*iter = 'd';
				break;
			case symlink:
				*iter = 'l';
				std::get<4>(file_infos.back()) += " -> "s + read_symlink(entry).string();
				break;
			case junction:
				*iter = 'j';
				std::get<4>(file_infos.back()) += " -> "s + read_symlink(entry).string();
				break;
			default:
				*iter = '-';
				break;
		}

		using enum std::filesystem::perms;
		constexpr static std::array perms{
			owner_read, owner_write, owner_exec,
			group_read, group_write, group_exec,
			others_read, others_write, others_exec
		};
		for (const auto &[perm, op] : std::views::zip(perms, "rwxrwxrwx"sv))
		{
			*++iter = (stat.permissions() & perm) == none ? '-' : op;
		}
	}

	auto max_width = [&file_infos]<std::size_t Index> {
		return file_infos.size() == 0 ? 0 : std::ranges::max(file_infos | std::views::elements<Index> | std::views::transform(&std::string::length));
	};
	auto max_width1{ max_width.operator()<1>() };
	auto max_width2{ max_width.operator()<2>() };
	for (const auto &[type_and_perms, hard_link_count, file_size, last_write_time, filename] : file_infos)
	{
		std::println("{} {:>{}} {:>{}} {} {}", type_and_perms, hard_link_count, max_width1, file_size, max_width2, last_write_time, filename);
	}
}

void priv_mkdir(const std::filesystem::path &path)
{
	std::println("Directory created: {}", create_directories(path));
}

void priv_remove(const std::filesystem::path &path)
{
	std::println("Removed {} file(s)", remove_all(path));
}

void priv_move(const std::filesystem::path &old_path, const std::filesystem::path &new_path)
{
	rename(old_path, new_path);
}

#pragma push_macro("REG_TYPE")
#undef REG_TYPE
#define REG_TYPE(t) std::make_pair(REG_##t, TEXT(#t##sv))
inline static const std::unordered_map reg_type_map{
	REG_TYPE(NONE),
	REG_TYPE(SZ),
	REG_TYPE(EXPAND_SZ),
	REG_TYPE(BINARY),
	REG_TYPE(DWORD),
	REG_TYPE(DWORD_BIG_ENDIAN),
	REG_TYPE(LINK),
	REG_TYPE(MULTI_SZ),
	REG_TYPE(QWORD)
};
#undef REG_TYPE
#pragma pop_macro("REG_TYPE")

inline static const auto reg_typename_map{ std::views::zip(reg_type_map | std::views::values, reg_type_map | std::views::keys) | std::ranges::to<std::unordered_map>() };

void priv_getkv(std::tstring_view path)
{
	HKey	hkey(path, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE);
	LSTATUS ec;

	for (DWORD i{};; ++i)
	{
		TCHAR name[16384]{};
		DWORD name_len{ 16384 }, data_len{};
		ec = RegEnumValue(hkey, i, name, &name_len,
						  nullptr, nullptr, nullptr, &data_len);
		switch (ec)
		{
			case ERROR_SUCCESS:
				break;
			case ERROR_NO_MORE_ITEMS:
				return;
			default:
				SetLastError(ec);
				throw_last_error("RegEnumValue"sv);
		}

		DWORD			  type{};
		std::vector<BYTE> data(data_len);
		ec = RegQueryValueEx(hkey, name, nullptr,
							 &type, data.data(), &data_len);
		if (ec != ERROR_SUCCESS)
		{
			SetLastError(ec);
			throw_last_error("RegQueryValueEx"sv);
		}

		std::println("[{}]", i + 1);
		tprintln(TEXT("Name: {:.{}}"), name, name_len);
		tprintln(TEXT("Type: {} (REG_{})"), type, reg_type_map.contains(type) ? reg_type_map.at(type) : TEXT("<unknown>"sv));
		if (data_len == 0)
		{
			std::println("Value: <empty>");
			continue;
		}
		switch (type)
		{
			case REG_SZ:
			case REG_EXPAND_SZ:
				tprintln(TEXT("Value: {}"), reinterpret_cast<LPTSTR>(data.data()));
				break;
			case REG_DWORD:
				std::println("Value: {:#010x}", *reinterpret_cast<DWORD *>(data.data()));
				break;
			case REG_DWORD_BIG_ENDIAN:
				std::println("Value: {:#010x}", std::byteswap(*reinterpret_cast<DWORD *>(data.data())));
				break;
			case REG_LINK:
				stdext::wprintln(L"Value: {:.{}}", reinterpret_cast<LPCWSTR>(data.data()), data_len / sizeof(WCHAR));
				break;
			case REG_MULTI_SZ:
				tprintln(TEXT("Value: {::?s}"),
						 std::tstring_view(reinterpret_cast<LPCTSTR>(data.data()), data_len / sizeof(TCHAR)) |
							 std::views::split(TEXT('\0')) |
							 std::views::take_while(std::not_fn(std::ranges::empty)));
				break;
			case REG_QWORD:
				std::println("Value: {:#018x}", *reinterpret_cast<unsigned long long *>(data.data()));
				break;
			default:
				std::println("Value: {:n:02x}", data);
				break;
		}
	}
}

template <class DataType>
void priv_setkv(std::tstring_view path, std::tstring_view name, std::tstring_view type, DataType &&data)
	requires std::ranges::contiguous_range<DataType> &&
			 std::same_as<std::ranges::range_value_t<DataType>, BYTE>
{
	HKey hkey(path,
			  REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
			  REG_OPTION_BACKUP_RESTORE | (type == TEXT("LINK"sv) ? REG_OPTION_CREATE_LINK : 0),
			  KEY_SET_VALUE);

	auto iter{ reg_typename_map.find(type) };
	if (iter == reg_typename_map.end())
	{
		throw std::invalid_argument("Invalid registry key value type.");
	}

	if (auto ec{ RegSetValueEx(hkey, name.data(), 0, iter->second,
							   std::ranges::data(data), static_cast<DWORD>(std::ranges::size(data))) };
		ec != ERROR_SUCCESS)
	{
		SetLastError(ec);
		throw_last_error("RegSetValueEx"sv);
	}
}

void priv_delkv(std::tstring_view path, std::tstring_view name)
{
	HKey hkey(path, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_SET_VALUE);
	if (auto ec{ RegDeleteValue(hkey, name.data()) };
		ec != ERROR_SUCCESS)
	{
		SetLastError(ec);
		throw_last_error("RegDeleteValue"sv);
	}
}

void priv_listkey(std::tstring_view path)
{
	HKey hkey(path, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_ENUMERATE_SUB_KEYS);
	for (DWORD i{};; ++i)
	{
		TCHAR	 name[256]{};
		DWORD	 name_len{ 256 };
		FILETIME last_write_time;
		switch (auto ec{ RegEnumKeyEx(hkey, i, name, &name_len,
									  nullptr, nullptr, nullptr, &last_write_time) };
				ec)
		{
			case ERROR_SUCCESS:
				break;
			case ERROR_NO_MORE_ITEMS:
				return;
			default:
				SetLastError(ec);
				throw_last_error("RegEnumKeyEx"sv);
		}

		using FileTime = std::filesystem::file_time_type;
		FileTime tp(FileTime::duration(static_cast<FileTime::rep>(last_write_time.dwHighDateTime) << (sizeof(FILETIME::dwHighDateTime) * 8) | last_write_time.dwLowDateTime));
		tprintln(TEXT("{:%FT%T%z} {:.{}}"),
				 std::chrono::zoned_time(std::chrono::current_zone(),
										 clock_cast<std::chrono::system_clock>(tp)),
				 name, name_len);
	}
}

void priv_delkey(std::tstring_view path)
{
	auto [reg_root, sub_key] = HKey::reg_split(path);
	if (auto ec{ RegDeleteKey(reg_root, sub_key) };
		ec != ERROR_SUCCESS)
	{
		if (ec == ERROR_ACCESS_DENIED)
		{
			std::println(stderr, "[INFO] To delete a key, you need DELETE access to it. The key to be deleted must not have subkeys.");
		}
		SetLastError(ec);
		throw_last_error("RegDeleteKey"sv);
	}
}

void priv_renkey(std::tstring_view path, const std::filesystem::path &new_name)
{
	HKey hkey(path, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_WRITE);
	if (auto ec{ RegRenameKey(hkey, nullptr, new_name.c_str()) };
		ec != ERROR_SUCCESS)
	{
		if (ec == ERROR_ACCESS_DENIED)
		{
			std::println(stderr, "[INFO] To rename a key, you need KEY_WRITE and DELETE access to it, and KEY_CREATE_SUB_KEY access to its parent key.");
		}
		SetLastError(ec);
		throw_last_error("RegRenameKey"sv);
	}
}

struct SidInfo {
#pragma push_macro("SID_TYPE")
#undef SID_TYPE
#define SID_TYPE(t) std::make_pair(SidType##t, TEXT(#t##sv))
	inline static const std::unordered_map sid_type_map{
		SID_TYPE(User),
		SID_TYPE(Group),
		SID_TYPE(Domain),
		SID_TYPE(Alias),
		SID_TYPE(WellKnownGroup),
		SID_TYPE(DeletedAccount),
		SID_TYPE(Invalid),
		SID_TYPE(Unknown),
		SID_TYPE(Computer),
		SID_TYPE(Label),
		SID_TYPE(LogonSession)
	};
#undef SID_TYPE
#pragma pop_macro("SID_TYPE")

	String			  str;
	std::tstring	  name;
	std::tstring_view type;

	SidInfo(PSID sid)
	{
		if (ConvertSidToStringSid(sid, &str) == FALSE)
		{
			throw_last_error("ConvertSidToStringSid"sv);
		}

		DWORD		 domain_len{}, name_len{};
		SID_NAME_USE sid_type;
		LookupAccountSid(nullptr, sid, nullptr, &name_len,
						 nullptr, &domain_len, &sid_type);
		switch (GetLastError())
		{
			case ERROR_INSUFFICIENT_BUFFER:
				break;
			case ERROR_NONE_MAPPED:
				name = TEXT("<none mapped>"s);
				type = TEXT("<unknown>"sv);
				return;
			default:
				throw_last_error("LookupAccountSid"sv);
		}

		name.resize(domain_len + name_len - 1);
		if (LookupAccountSid(nullptr, sid, name.data() + domain_len, &name_len,
							 name.data(), &domain_len, &sid_type) == FALSE)
		{
			throw_last_error("LookupAccountSid"sv);
		}
		name[domain_len] = TEXT('\\');

		type = sid_type_map.contains(sid_type) ? sid_type_map.at(sid_type) : TEXT("<unknown>"sv);
	}
};

inline constexpr static auto common_security_information{
	OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
	LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION | ACCESS_FILTER_SECURITY_INFORMATION
};

#pragma push_macro("ACE_ACCESS")
#undef ACE_ACCESS
#define ACE_ACCESS(a) std::make_pair<ACCESS_MASK>(a, TEXT(#a##sv))
inline constexpr static std::tuple standard_access_map{
	ACE_ACCESS(DELETE),
	ACE_ACCESS(READ_CONTROL),
	ACE_ACCESS(WRITE_DAC),
	ACE_ACCESS(WRITE_OWNER),
	ACE_ACCESS(SYNCHRONIZE),
	ACE_ACCESS(ACCESS_SYSTEM_SECURITY),
	ACE_ACCESS(MAXIMUM_ALLOWED),
	ACE_ACCESS(GENERIC_ALL),
	ACE_ACCESS(GENERIC_EXECUTE),
	ACE_ACCESS(GENERIC_WRITE),
	ACE_ACCESS(GENERIC_READ)
};

template <SE_OBJECT_TYPE SeObjectType>
inline constexpr static auto ace_access_map = std::apply([](auto &&...args) { return std::array{ args... }; }, standard_access_map);

template <>
inline constexpr auto ace_access_map<SE_FILE_OBJECT> = std::apply(
	[](auto &&...args) {
		return std::array{
			ACE_ACCESS(FILE_READ_DATA | FILE_LIST_DIRECTORY),
			ACE_ACCESS(FILE_WRITE_DATA | FILE_ADD_FILE),
			ACE_ACCESS(FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY | FILE_CREATE_PIPE_INSTANCE),
			ACE_ACCESS(FILE_READ_EA),
			ACE_ACCESS(FILE_WRITE_EA),
			ACE_ACCESS(FILE_EXECUTE | FILE_TRAVERSE),
			ACE_ACCESS(FILE_DELETE_CHILD),
			ACE_ACCESS(FILE_READ_ATTRIBUTES),
			ACE_ACCESS(FILE_WRITE_ATTRIBUTES),
			args...
		};
	},
	standard_access_map);

template <>
inline constexpr auto ace_access_map<SE_REGISTRY_KEY> = std::apply(
	[](auto &&...args) {
		return std::array{
			ACE_ACCESS(KEY_QUERY_VALUE),
			ACE_ACCESS(KEY_SET_VALUE),
			ACE_ACCESS(KEY_CREATE_SUB_KEY),
			ACE_ACCESS(KEY_ENUMERATE_SUB_KEYS),
			ACE_ACCESS(KEY_NOTIFY),
			ACE_ACCESS(KEY_CREATE_LINK),
			ACE_ACCESS(KEY_WOW64_64KEY),
			ACE_ACCESS(KEY_WOW64_32KEY),
			ACE_ACCESS(KEY_WOW64_RES),
			args...
		};
	},
	standard_access_map);
#undef ACE_ACCESS
#pragma pop_macro("ACE_ACCESS")

template <SE_OBJECT_TYPE SeObjectType, class AceType>
	requires requires(AceType ace) {
		{ ace.Mask } -> std::common_reference_with<ACCESS_MASK>;
		{ ace.SidStart } -> std::common_reference_with<DWORD>;
	}
inline void print_ace(AceType *ace)
{
	SidInfo sid_info(&ace->SidStart);
	tprintln(TEXT("Access: {:#010x} {}"), ace->Mask,
			 ace_access_map<SeObjectType> | std::views::filter([ace](const auto &pair) { return (ace->Mask & pair.first) != 0; }) | std::views::values);
	tprintln(TEXT("User: {} (SID: {}) (Type: {})"), sid_info.name, LPTSTR(sid_info.str), sid_info.type);
}

#pragma push_macro("ACE_FLAG")
#undef ACE_FLAG
#define ACE_FLAG(f) std::make_pair(f, TEXT(#f##sv))
inline constexpr static std::array ace_flag_map{
	ACE_FLAG(OBJECT_INHERIT_ACE),
	ACE_FLAG(CONTAINER_INHERIT_ACE),
	ACE_FLAG(NO_PROPAGATE_INHERIT_ACE),
	ACE_FLAG(INHERIT_ONLY_ACE),
	ACE_FLAG(INHERITED_ACE),
	ACE_FLAG(CRITICAL_ACE_FLAG),
	ACE_FLAG(SUCCESSFUL_ACCESS_ACE_FLAG),
	ACE_FLAG(FAILED_ACCESS_ACE_FLAG)
};
#undef ACE_FLAG
#pragma pop_macro("ACE_FLAG")

template <SE_OBJECT_TYPE SeObjectType>
inline void print_acl(PACL acl)
{
	if (acl == nullptr)
	{
		return;
	}

	ACL_SIZE_INFORMATION acl_size_info;
	if (GetAclInformation(acl, &acl_size_info, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation) == FALSE)
	{
		throw_last_error("GetAclInformation"sv);
	}

	for (DWORD i{}; i < acl_size_info.AceCount; ++i)
	{
		PACE_HEADER ace_header;
		if (GetAce(acl, i, reinterpret_cast<LPVOID *>(&ace_header)) == FALSE)
		{
			throw_last_error("GetAce"sv);
		}

		std::println("[{}]", i + 1);
		tprintln(TEXT("Flags: {:#04x} {}"), ace_header->AceFlags,
				 ace_flag_map | std::views::filter([ace_header](const auto &pair) { return (ace_header->AceFlags & pair.first) != 0; }) | std::views::values);
		std::print("Type: {:#04x}", ace_header->AceType);
		switch (ace_header->AceType)
		{
#pragma push_macro("CASE_ACE_TYPE")
#undef CASE_ACE_TYPE
#define CASE_ACE_TYPE(t)                                                   \
	case t##_ACE_TYPE:                                                     \
		std::println(" (" #t ")");                                         \
		print_ace<SeObjectType>(reinterpret_cast<P##t##_ACE>(ace_header)); \
		break;

			CASE_ACE_TYPE(ACCESS_ALLOWED)
			CASE_ACE_TYPE(ACCESS_DENIED)
			CASE_ACE_TYPE(SYSTEM_AUDIT)
			CASE_ACE_TYPE(SYSTEM_ALARM)
			// CASE_ACE_TYPE(ACCESS_ALLOWED_COMPOUND)
			CASE_ACE_TYPE(ACCESS_ALLOWED_OBJECT)
			CASE_ACE_TYPE(ACCESS_DENIED_OBJECT)
			CASE_ACE_TYPE(SYSTEM_AUDIT_OBJECT)
			CASE_ACE_TYPE(SYSTEM_ALARM_OBJECT)
			CASE_ACE_TYPE(ACCESS_ALLOWED_CALLBACK)
			CASE_ACE_TYPE(ACCESS_DENIED_CALLBACK)
			CASE_ACE_TYPE(ACCESS_ALLOWED_CALLBACK_OBJECT)
			CASE_ACE_TYPE(ACCESS_DENIED_CALLBACK_OBJECT)
			CASE_ACE_TYPE(SYSTEM_AUDIT_CALLBACK)
			CASE_ACE_TYPE(SYSTEM_ALARM_CALLBACK)
			CASE_ACE_TYPE(SYSTEM_AUDIT_CALLBACK_OBJECT)
			CASE_ACE_TYPE(SYSTEM_ALARM_CALLBACK_OBJECT)
			CASE_ACE_TYPE(SYSTEM_MANDATORY_LABEL)
			CASE_ACE_TYPE(SYSTEM_RESOURCE_ATTRIBUTE)
			CASE_ACE_TYPE(SYSTEM_SCOPED_POLICY_ID)
			CASE_ACE_TYPE(SYSTEM_PROCESS_TRUST_LABEL)
			CASE_ACE_TYPE(SYSTEM_ACCESS_FILTER)
			default:
				std::println();
				break;

#undef CASE_ACE_TYPE
#pragma pop_macro("CASE_ACE_TYPE")
		}
	}
}

inline auto security_descriptor_split(const SecurityDescriptor &sd)
{
	PSID owner_sid, group_sid;
	PACL dacl{ nullptr }, sacl{ nullptr };
	BOOL _;
	if (GetSecurityDescriptorOwner(sd, &owner_sid, &_) == FALSE)
	{
		throw_last_error("GetSecurityDescriptorOwner"sv);
	}
	if (GetSecurityDescriptorGroup(sd, &group_sid, &_) == FALSE)
	{
		throw_last_error("GetSecurityDescriptorGroup"sv);
	}
	if (GetSecurityDescriptorDacl(sd, &_, &dacl, &_) == FALSE)
	{
		throw_last_error("GetSecurityDescriptorDacl"sv);
	}
	if (GetSecurityDescriptorSacl(sd, &_, &sacl, &_) == FALSE)
	{
		throw_last_error("GetSecurityDescriptorSacl"sv);
	}
	return std::make_tuple(owner_sid, group_sid, dacl, sacl);
}

template <SE_OBJECT_TYPE SeObjectType>
void priv_getacl(const std::filesystem::path &path)
{
	SecurityDescriptor sd;

	PSID owner_sid, group_sid;
	PACL dacl, sacl;

	auto sec_info{ PROCESS_TRUST_LABEL_SECURITY_INFORMATION | BACKUP_SECURITY_INFORMATION | common_security_information };
	if constexpr (SeObjectType == SE_REGISTRY_KEY)
	{
		HKey	hkey(path.tstring(), REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
		LSTATUS ec;

		ec = GetSecurityInfo(hkey, SeObjectType, sec_info,
							 &owner_sid, &group_sid, &dacl, &sacl, &sd);
		if (ec != ERROR_SUCCESS)
		{
			if (ec != ERROR_ACCESS_DENIED)
			{
				SetLastError(ec);
				throw_last_error("GetSecurityInfo"sv);
			}
			std::println(stderr, "[INFO] GetSecurityInfo() returned ERROR_ACCESS_DENIED. Trying RegGetKeySecurity() instead.");

			DWORD sd_len{};
			ec = RegGetKeySecurity(hkey, sec_info, nullptr, &sd_len);
			if (ec != ERROR_INSUFFICIENT_BUFFER)
			{
				SetLastError(ec);
				throw_last_error("RegGetKeySecurity"sv);
			}

			sd = LocalAlloc(LMEM_FIXED, sd_len);
			if (!sd.valid())
			{
				throw_last_error("LocalAlloc"sv);
			}

			ec = RegGetKeySecurity(hkey, sec_info, sd, &sd_len);
			if (ec != ERROR_SUCCESS)
			{
				SetLastError(ec);
				throw_last_error("RegGetKeySecurity"sv);
			}
			std::tie(owner_sid, group_sid, dacl, sacl) = security_descriptor_split(sd);
		}
	}
	else
	{
		if (auto ec{ GetNamedSecurityInfo(path.tstring().c_str(), SeObjectType, sec_info,
										  &owner_sid, &group_sid, &dacl, &sacl, &sd) };
			ec != ERROR_SUCCESS)
		{
			SetLastError(ec);
			throw_last_error("GetNamedSecurityInfo"sv);
		}
	}

	String sd_str;
	if (ConvertSecurityDescriptorToStringSecurityDescriptor(
			sd, SDDL_REVISION_1,
			PROCESS_TRUST_LABEL_SECURITY_INFORMATION | common_security_information,
			&sd_str, nullptr) == FALSE)
	{
		throw_last_error("ConvertSecurityDescriptorToStringSecurityDescriptor"sv);
	}
	tprintln(TEXT("Security Descriptor: {}"), LPTSTR(sd_str));
	std::println();

	SidInfo owner_sid_info(owner_sid), group_sid_info(group_sid);
	tprintln(TEXT("Owner: {} (SID: {}) (Type: {})"),
			 owner_sid_info.name, LPTSTR(owner_sid_info.str), owner_sid_info.type);
	tprintln(TEXT("Group: {} (SID: {}) (Type: {})"),
			 group_sid_info.name, LPTSTR(group_sid_info.str), group_sid_info.type);
	std::println();

	std::println("DACL:");
	print_acl<SeObjectType>(dacl);
	std::println();
	std::println("SACL:");
	print_acl<SeObjectType>(sacl);
}

template <SE_OBJECT_TYPE SeObjectType>
void priv_setacl(const std::filesystem::path &path, std::tstring_view sddl, bool inherit)
{
	SecurityDescriptor sd;

	if (ConvertStringSecurityDescriptorToSecurityDescriptor(
			sddl.data(), SDDL_REVISION_1,
			&sd, nullptr) == FALSE)
	{
		throw_last_error("ConvertStringSecurityDescriptorToSecurityDescriptor"sv);
	}

	auto [owner_sid, group_sid, dacl, sacl] = security_descriptor_split(sd);
	auto sec_info{
		(inherit ? (UNPROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION)
				 : (PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION)) |
		BACKUP_SECURITY_INFORMATION | common_security_information
	};

	if constexpr (SeObjectType == SE_REGISTRY_KEY)
	{
		HKey	hkey(path.tstring(), REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY);
		LSTATUS ec;

		ec = SetSecurityInfo(hkey, SeObjectType, sec_info,
							 owner_sid, group_sid, dacl, sacl);
		if (ec != ERROR_SUCCESS)
		{
			if (ec != ERROR_ACCESS_DENIED)
			{
				SetLastError(ec);
				throw_last_error("SetSecurityInfo"sv);
			}
			std::println(stderr, "[INFO] SetSecurityInfo() returned ERROR_ACCESS_DENIED. Trying RegSetKeySecurity() instead, which cannot inherit/propagate ACEs.");

			ec = RegSetKeySecurity(hkey, sec_info, sd);
			if (ec != ERROR_SUCCESS)
			{
				SetLastError(ec);
				throw_last_error("RegSetKeySecurity"sv);
			}
		}
	}
	else
	{
		if (auto ec{ SetNamedSecurityInfo(path.tstring().data(), SeObjectType, sec_info,
										  owner_sid, group_sid, dacl, sacl) };
			ec != ERROR_SUCCESS)
		{
			SetLastError(ec);
			throw_last_error("SetNamedSecurityInfo"sv);
		}
	}
}

int _tmain(int argc, TCHAR **argv)
try
{
	auto equal{ std::bind_back(std::equal_to{}, argv[1]) };

	constexpr static std::array single_arg_commands{ TEXT("list"sv), TEXT("mkdir"sv), TEXT("remove"sv), TEXT("getkv"sv), TEXT("listkey"sv), TEXT("delkey"sv), TEXT("getfacl"sv), TEXT("getkacl"sv) };
	constexpr static std::array double_arg_commands{ TEXT("read"sv), TEXT("write"sv), TEXT("move"sv), TEXT("delkv"sv), TEXT("renkey"sv), TEXT("setfacl"sv), TEXT("setfiacl"sv), TEXT("setkacl"sv), TEXT("setkiacl"sv) };

	if (!(argc == 3 && (std::ranges::any_of(single_arg_commands, equal))) &&
		!(argc == 4 && (std::ranges::any_of(double_arg_commands, equal))) &&
		!(argc >= 5 && argv[1] == TEXT("setkv"sv)))
	{
		std::println("Usage:");
		tprintln(TEXT("(1)  \"{}\" read <infile> <outfile>"), argv[0]);
		tprintln(TEXT("(2)  \"{}\" write <infile> <outfile>"), argv[0]);
		tprintln(TEXT("(3)  \"{}\" list <directory>"), argv[0]);
		tprintln(TEXT("(4)  \"{}\" mkdir <directory>"), argv[0]);
		tprintln(TEXT("(5)  \"{}\" remove <file>"), argv[0]);
		tprintln(TEXT("(6)  \"{}\" move <old path> <new path>"), argv[0]);
		tprintln(TEXT("(7)  \"{}\" getkv <registry>"), argv[0]);
		tprintln(TEXT("(8)  \"{}\" setkv <registry> <name> <type> [<byte> ...]"), argv[0]);
		tprintln(TEXT("     <type>: {}"), reg_type_map | std::views::values);
		tprintln(TEXT("     <byte>: 00-ff"));
		tprintln(TEXT("(9)  \"{}\" delkv <registry> <name>"), argv[0]);
		tprintln(TEXT("(10) \"{}\" listkey <registry>"), argv[0]);
		tprintln(TEXT("(11) \"{}\" delkey <registry>"), argv[0]);
		tprintln(TEXT("(12) \"{}\" renkey <registry> <new name>"), argv[0]);
		tprintln(TEXT("(13) \"{}\" getfacl|getkacl <file|registry>"), argv[0]);
		tprintln(TEXT("(14) \"{}\" setf(i)acl|setk(i)acl <file|registry> <sddl>"), argv[0]);
		return 0;
	}

	acquire_privileges();

	if (argv[1] == TEXT("read"sv))
	{
		priv_read(argv[2], argv[3]);
	}
	else if (argv[1] == TEXT("write"sv))
	{
		priv_write(argv[2], argv[3]);
	}
	else if (argv[1] == TEXT("list"sv))
	{
		priv_list(argv[2]);
	}
	else if (argv[1] == TEXT("mkdir"sv))
	{
		priv_mkdir(argv[2]);
	}
	else if (argv[1] == TEXT("remove"sv))
	{
		priv_remove(argv[2]);
	}
	else if (argv[1] == TEXT("move"sv))
	{
		priv_move(argv[2], argv[3]);
	}
	else if (argv[1] == TEXT("getkv"sv))
	{
		priv_getkv(argv[2]);
	}
	else if (argv[1] == TEXT("setkv"sv))
	{
		priv_setkv(argv[2], argv[3], argv[4],
				   std::ranges::subrange(argv + 5, argv + argc) |
					   std::views::transform([](const auto &s) { return static_cast<BYTE>(std::stoul(s, nullptr, 16)); }) |
					   std::ranges::to<std::vector>());
	}
	else if (argv[1] == TEXT("delkv"sv))
	{
		priv_delkv(argv[2], argv[3]);
	}
	else if (argv[1] == TEXT("listkey"sv))
	{
		priv_listkey(argv[2]);
	}
	else if (argv[1] == TEXT("delkey"sv))
	{
		priv_delkey(argv[2]);
	}
	else if (argv[1] == TEXT("renkey"sv))
	{
		priv_renkey(argv[2], argv[3]);
	}
	else if (argv[1] == TEXT("getfacl"sv))
	{
		priv_getacl<SE_FILE_OBJECT>(argv[2]);
	}
	else if (argv[1] == TEXT("getkacl"sv))
	{
		priv_getacl<SE_REGISTRY_KEY>(argv[2]);
	}
	else if (argv[1] == TEXT("setfacl"sv) || argv[1] == TEXT("setfiacl"sv))
	{
		priv_setacl<SE_FILE_OBJECT>(argv[2], argv[3], argv[1] == TEXT("setfiacl"sv));
	}
	else if (argv[1] == TEXT("setkacl"sv) || argv[1] == TEXT("setkiacl"sv))
	{
		priv_setacl<SE_REGISTRY_KEY>(argv[2], argv[3], argv[1] == TEXT("setkiacl"sv));
	}
	return 0;
}
catch (const std::exception &e)
{
	std::println(stderr, "[Error] {}", e.what());
}
