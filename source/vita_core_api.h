#pragma once

#if defined( _WIN32 )
#if defined( vita_core_api_STATIC )
#define VITA_CORE_API extern "C"
#elif defined( vita_core_api_EXPORTS )
#define VITA_CORE_API extern "C" __declspec(dllexport)
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API extern "C" __declspec(dllimport)
#endif // vita_core_api_EXPORTS
#elif defined( __GNUC__ )
#define __cdecl    /* nothing */
#define __fastcall /* nothing */
#define __stdcall  /* nothing */
#if defined( vita_core_api_EXPORTS )
#define VITA_CORE_API extern "C" __attribute__ ((visibility("default")))
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API extern "C"
#endif // vita_core_api_EXPORTS
#else // !_WIN32
#define __cdecl    /* nothing */
#define __fastcall /* nothing */
#define __stdcall  /* nothing */
#if defined( vita_core_api_EXPORTS )
#define VITA_CORE_API extern "C"
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API extern "C"
#endif // vita_core_api_EXPORTS
#endif

struct ivita_core_runtime_ipcchannel_client
{
};

VITA_CORE_API ivita_core_runtime_ipcchannel_client* vita_core_runtime_ipcchannel_client();

VITA_CORE_API int vita_core_runtime_ipcchannel_client_is_ready();

VITA_CORE_API int vita_core_runtime_ipcchannel_client_is_ready_ex(const char* channel_name);

VITA_CORE_API size_t vita_core_runtime_ipcchannel_client_request(
        const wchar_t* input,
        wchar_t* output,
        size_t count
);

VITA_CORE_API int vita_core_runtime_ipcchannel_client_set_name(const char* name);
