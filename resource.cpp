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
#include <fstream>
#include <print>
#include <ranges>
#include <unordered_map>
#include <vector>

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

template <class T>
	requires std::convertible_to<T, std::tstring_view> || std::integral<std::remove_cvref_t<T>>
inline LPCTSTR make_resource(T &&id)
{
	using BaseT = std::remove_cvref_t<T>;
	if constexpr (std::integral<BaseT>)
	{
		return MAKEINTRESOURCE(id);
	}
	else
	{
		LPCTSTR ret{ nullptr };
		if constexpr (std::same_as<BaseT, std::tstring_view>)
		{
			ret = id.data();
		}
		else if constexpr (std::same_as<BaseT, std::tstring>)
		{
			ret = id.c_str();
		}
		else
		{
			ret = id;
		}
		if (!IS_INTRESOURCE(ret) && *ret == TEXT('#'))
		{
			return MAKEINTRESOURCE(std::stoul(++ret));
		}
		return ret;
	}
}

struct Resource {
#pragma pack(push, 2)
	struct IconDirEntry {
		BYTE  width;
		BYTE  height;
		BYTE  color_count;
		BYTE  reserved;
		WORD  planes;
		WORD  bit_count;
		DWORD bytes_in_res;
		WORD  id;
	};

	struct IconDir {
		WORD		 reserved;
		WORD		 type;
		WORD		 count;
		IconDirEntry entries[1];
	};
#pragma pack(pop)

#pragma push_macro("RES_TYPE")
#undef RES_TYPE
#define RES_TYPE(t) std::make_pair(TEXT(#t##sv), RT_##t)
	inline static const std::unordered_map types{
		RES_TYPE(CURSOR),
		RES_TYPE(BITMAP),
		RES_TYPE(ICON),
		RES_TYPE(MENU),
		RES_TYPE(DIALOG),
		RES_TYPE(STRING),
		RES_TYPE(FONTDIR),
		RES_TYPE(FONT),
		RES_TYPE(ACCELERATOR),
		RES_TYPE(RCDATA),
		RES_TYPE(MESSAGETABLE),
		RES_TYPE(GROUP_CURSOR),
		RES_TYPE(GROUP_ICON),
		RES_TYPE(VERSION),
		RES_TYPE(DLGINCLUDE),
		RES_TYPE(PLUGPLAY),
		RES_TYPE(VXD),
		RES_TYPE(ANICURSOR),
		RES_TYPE(ANIICON),
		RES_TYPE(HTML),
		RES_TYPE(MANIFEST)
	};
#undef RES_TYPE
#pragma pop_macro("RES_TYPE")

	LPCTSTR		type;
	LPCTSTR		name;
	std::string data;
};

template <>
struct std::formatter<Resource, TCHAR> : std::formatter<std::tstring, TCHAR> {
	using Base = std::formatter<std::tstring, TCHAR>;

	template <class FormatContext>
	auto format(const Resource &res, FormatContext &ctx) const
	{
		if (IS_INTRESOURCE(res.name))
		{
			Base::format(std::format(TEXT("#{}: "), reinterpret_cast<ULONG_PTR>(res.name)), ctx);
		}
		else
		{
			Base::format(std::format(TEXT("{}: "), res.name), ctx);
		}

		if (res.type != RT_GROUP_ICON)
		{
			return Base::format(std::format(TEXT("<{} byte(s)>"), res.data.length()), ctx);
		}

		auto icon_dir{ reinterpret_cast<const Resource::IconDir *>(res.data.data()) };
		Base::format(std::format(TEXT("<{} icon(s)>"), icon_dir->count), ctx);
		for (WORD i{}; i < icon_dir->count; ++i)
		{
			auto &entry{ icon_dir->entries[i] };
			Base::format(std::format(
							 TEXT("\n[{}] <{} byte(s)> ({}x{}, {} color(s), {} bit(s), {} plane(s))"),
							 entry.id, entry.bytes_in_res, entry.width, entry.height,
							 entry.color_count, entry.bit_count, entry.planes),
						 ctx);
		}
		return ctx.out();
	}
};

class ResourceReader {
private:
	LibraryLoader hdl;

	static BOOL CALLBACK enum_proc(HMODULE, LPCTSTR, LPTSTR name, LONG_PTR param)
	{
		auto names{ reinterpret_cast<std::vector<std::tstring> *>(param) };
		if (IS_INTRESOURCE(name))
		{
			names->emplace_back(std::format(TEXT("#{}"), reinterpret_cast<ULONG_PTR>(name)));
		}
		else
		{
			names->emplace_back(name);
		}
		return TRUE;
	}

public:
	ResourceReader(std::tstring_view path)
		: hdl(path, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE) {}

	ResourceReader(const ResourceReader &)			  = delete;
	ResourceReader(ResourceReader &&)				  = delete;
	ResourceReader &operator=(const ResourceReader &) = delete;
	ResourceReader &operator=(ResourceReader &&)	  = delete;

	Resource get_resource(auto &&type, auto &&name)
	{
		auto type_str{ make_resource(std::forward<decltype(type)>(type)) };
		auto name_str{ make_resource(std::forward<decltype(name)>(name)) };

		auto res_info{ FindResource(hdl, name_str, type_str) };
		if (res_info == nullptr)
		{
			throw_last_error("FindResource"sv);
		}

		auto res_hdl{ LoadResource(hdl, res_info) };
		if (res_hdl == nullptr)
		{
			throw_last_error("LoadResource"sv);
		}

		auto res_data{ LockResource(res_hdl) };
		if (res_data == nullptr)
		{
			return {};
		}

		return { type_str, name_str,
				 std::string(static_cast<const char *>(res_data), SizeofResource(hdl, res_info)) };
	}

	void get_names(auto &&type, std::vector<std::tstring> &names)
	{
		auto type_str{ make_resource(std::forward<decltype(type)>(type)) };

		EnumResourceNames(hdl, type_str, enum_proc, reinterpret_cast<LONG_PTR>(&names));
	}
};

class ResourceWriter {
private:
	HANDLE hdl;

public:
	ResourceWriter(std::tstring_view path, bool delete_existing = false)
		: hdl{ BeginUpdateResource(path.data(), delete_existing) }
	{
		if (hdl == nullptr)
		{
			throw_last_error("BeginUpdateResource"sv);
		}
	}

	~ResourceWriter()
	{
		if (hdl != nullptr)
		{
			if (EndUpdateResource(hdl, FALSE) == FALSE)
			{
				throw_last_error("EndUpdateResource"sv);
			}
		}
	}

	ResourceWriter(const ResourceWriter &)			  = delete;
	ResourceWriter(ResourceWriter &&)				  = delete;
	ResourceWriter &operator=(const ResourceWriter &) = delete;
	ResourceWriter &operator=(ResourceWriter &&)	  = delete;

	void update_resource(auto &&type, auto &&name, std::string_view data)
	{
		auto type_str{ make_resource(std::forward<decltype(type)>(type)) };
		auto name_str{ make_resource(std::forward<decltype(name)>(name)) };

		if (UpdateResource(hdl, type_str, name_str,
						   MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
						   const_cast<char *>(data.data()), static_cast<DWORD>(data.length())) == FALSE)
		{
			throw_last_error("UpdateResource"sv);
		}
	}

	void delete_resource(auto &&type, auto &&name)
	{
		auto type_str{ make_resource(std::forward<decltype(type)>(type)) };
		auto name_str{ make_resource(std::forward<decltype(name)>(name)) };

		if (UpdateResource(hdl, type_str, name_str,
						   MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
						   nullptr, 0) == FALSE)
		{
			throw_last_error("UpdateResource"sv);
		}
	}
};

inline auto res_name_split(std::tstring_view res_names)
{
	return res_names | std::views::split(TEXT(',')) |
		   std::views::transform([](auto &&res_name) { return std::tstring(std::tstring_view(res_name)); });
}

void usage(std::tstring_view exe)
{
	std::println("Usage:");
	tprintln(TEXT("(1) \"{}\" list <module> [<type> #all|<name>[,<name>...] ...]"), exe);
	tprintln(TEXT("(2) \"{}\" update|replace <destination module> <source module> [<type> #all|<name>[,<name>...] ...]"), exe);
	tprintln(TEXT("(3) \"{}\" delete <module> [<type> #all|<name>[,<name>...] ...]"), exe);
	tprintln(TEXT("(4) \"{}\" dump <module> <dump file> <type> <name>"), exe);
	tprintln(TEXT("(5) \"{}\" load <module> <dump file> <type> <name>"), exe);
	tprintln(TEXT("<type>: {}"), Resource::types | std::views::keys);
	std::println("<name>: #<number>|<string>");
}

void res_list(int argc, TCHAR **argv)
{
	ResourceReader reader(argv[2]);
	for (int i{ 3 }; i + 1 < argc; i += 2)
	{
		tprintln(TEXT("[{}]"), argv[i]);
		auto iter{ Resource::types.find(argv[i]) };
		if (iter == Resource::types.end())
		{
			continue;
		}
		auto res_type{ iter->second };

		std::vector<std::tstring> res_names;
		if (argv[i + 1] == TEXT("#all"sv))
		{
			reader.get_names(res_type, res_names);
		}
		else
		{
			res_names.assign_range(res_name_split(argv[i + 1]));
		}

		for (const auto &res_name : res_names)
		{
			tprintln(TEXT("{}"), reader.get_resource(res_type, res_name));
		}
	}
}

void res_update(int argc, TCHAR **argv)
{
	ResourceReader reader(argv[3]);
	ResourceWriter writer(argv[2], argv[1] == TEXT("replace"sv));
	for (int i{ 4 }; i + 1 < argc; i += 2)
	{
		tprintln(TEXT("[{}]"), argv[i]);
		auto iter{ Resource::types.find(argv[i]) };
		if (iter == Resource::types.end())
		{
			continue;
		}
		auto res_type{ iter->second };

		std::vector<std::tstring> res_names;
		if (argv[i + 1] == TEXT("#all"sv))
		{
			reader.get_names(res_type, res_names);
		}
		else
		{
			res_names.assign_range(res_name_split(argv[i + 1]));
		}

		for (const auto &res_name : res_names)
		{
			auto res{ reader.get_resource(res_type, res_name) };
			tprintln(TEXT("{}"), res);
			writer.update_resource(res_type, res_name, res.data);
		}
	}
}

void res_delete(int argc, TCHAR **argv)
{
	ResourceWriter writer(argv[2]);
	for (int i{ 3 }; i < argc; i += 2)
	{
		tprintln(TEXT("[{}]"), argv[i]);
		auto iter{ Resource::types.find(argv[i]) };
		if (iter == Resource::types.end())
		{
			continue;
		}
		auto res_type{ iter->second };

		std::vector<std::tstring> res_names;
		if (argv[i + 1] == TEXT("#all"sv))
		{
			ResourceReader(argv[2]).get_names(res_type, res_names);
		}
		else
		{
			res_names.assign_range(res_name_split(argv[i + 1]));
		}

		for (auto &res_name : res_names)
		{
			tprintln(TEXT("{}"), res_name);
			writer.delete_resource(res_type, res_name);
		}
	}
}

void res_dump(TCHAR **argv)
{
	auto iter{ Resource::types.find(argv[4]) };
	if (iter == Resource::types.end())
	{
		return;
	}
	auto res_type{ iter->second };

	ResourceReader reader(argv[2]);
	std::ofstream  fout(argv[3], std::ios::binary | std::ios::noreplace);
	if (!fout.is_open())
	{
		throw_last_error("std::ofstream"sv);
	}

	auto data{ reader.get_resource(res_type, argv[5]).data };
	fout.write(data.c_str(), data.length());
}

void res_load(TCHAR **argv)
{
	auto iter{ Resource::types.find(argv[4]) };
	if (iter == Resource::types.end())
	{
		return;
	}
	auto res_type{ iter->second };

	ResourceWriter writer(argv[2]);
	std::ifstream  fin(argv[3], std::ios::binary);
	if (!fin.is_open())
	{
		throw_last_error("std::ifstream"sv);
	}

	std::string data(std::istreambuf_iterator(fin), {});
	writer.update_resource(res_type, argv[5], data);
}

int _tmain(int argc, TCHAR **argv)
try
{
	if (argc < 3)
	{
		usage(argv[0]);
		return 0;
	}

	if (argv[1] == TEXT("list"sv))
	{
		res_list(argc, argv);
	}
	else if (argv[1] == TEXT("update"sv) || argv[1] == TEXT("replace"sv))
	{
		if (argc < 4)
		{
			usage(argv[0]);
			return 0;
		}
		if (std::filesystem::equivalent(argv[2], argv[3]))
		{
			throw std::invalid_argument("Cannot update or replace the resources of a module with itself.");
		}
		res_update(argc, argv);
	}
	else if (argv[1] == TEXT("delete"sv))
	{
		res_delete(argc, argv);
	}
	else if (argv[1] == TEXT("dump"sv))
	{
		if (argc != 6)
		{
			usage(argv[0]);
			return 0;
		}
		res_dump(argv);
	}
	else if (argv[1] == TEXT("load"sv))
	{
		if (argc != 6)
		{
			usage(argv[0]);
			return 0;
		}
		res_load(argv);
	}
	else
	{
		usage(argv[0]);
	}
	return 0;
}
catch (const std::exception &e)
{
	std::println(stderr, "[Error] {}", e.what());
}
