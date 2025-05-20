#include <type_traits>

#include <Windows.h>

struct GetRemoteModuleHandleMessage {
	HMODULE handle;
	TCHAR	name[1];
};

extern "C"
	__declspec(dllexport)
	std::invoke_result_t<LPTHREAD_START_ROUTINE, GetRemoteModuleHandleMessage *>
		WINAPI
		get_remote_module_handle(GetRemoteModuleHandleMessage *msg)
{
	msg->handle = GetModuleHandle(msg->name);
	return {};
}
