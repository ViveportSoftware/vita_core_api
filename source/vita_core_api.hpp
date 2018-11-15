#pragma once

#if defined( _WIN32 )
#if defined( vita_core_api_STATIC )
#define VITA_CORE_API_CPP
#elif defined( vita_core_api_EXPORTS )
#define VITA_CORE_API_CPP __declspec(dllexport)
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API_CPP __declspec(dllimport)
#endif // vita_core_api_EXPORTS
#if defined( _MSC_FULL_VER ) && _MSC_FULL_VER >= 190000000
#define NOEXCEPT noexcept
#else
#define NOEXCEPT /* nothing */
#endif
#elif defined( __GNUC__ )
#define __cdecl    /* nothing */
#define __fastcall /* nothing */
#define __stdcall  /* nothing */
#if defined( vita_core_api_EXPORTS )
#define VITA_CORE_API_CPP __attribute__ ((visibility("default")))
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API_CPP
#endif // vita_core_api_EXPORTS
#else // !_WIN32
#define __cdecl    /* nothing */
#define __fastcall /* nothing */
#define __stdcall  /* nothing */
#if defined( vita_core_api_EXPORTS )
#define VITA_CORE_API_CPP
#else  // vita_core_api_EXPORTS
#define VITA_CORE_API_CPP
#endif // vita_core_api_EXPORTS
#endif

#include <string>

#include "vita_core_api.h"

namespace vita
{
    namespace core
    {
        namespace config
        {
            class VITA_CORE_API_CPP config
            {
            public:
                static config& get_instance();

                config(const config& other);
                config(config&& other) NOEXCEPT;
                config& operator=(const config& other);
                config& operator=(config&& other) NOEXCEPT;
                ~config();

                std::wstring get(
                        const std::wstring& key,
                        const std::wstring& default_value
                ) const;

            private:
                config();

                class impl;
                impl* impl_;
            };
        }

        namespace crypto
        {
            class VITA_CORE_API_CPP sha1
            {
            public:
                static std::string generate_from_utf8_string_in_hex(const std::string& utf8_string);
            };
        }

        namespace io
        {
            class VITA_CORE_API_CPP directory
            {
            public:
                static bool is_valid_and_writable(const std::wstring& path);
                static bool is_valid_and_writable(const std::string& path_in_utf8);
            };

            class VITA_CORE_API_CPP file
            {
            public:
                static bool exist(const std::wstring& file);
                static bool exist(const std::string& file_in_utf8);
            };
        }

        namespace log
        {
            class VITA_CORE_API_CPP logger
            {
            public:
                static logger& get_instance();

                logger(const logger& other);
                logger(logger&& other) NOEXCEPT;
                logger& operator=(const logger& other);
                logger& operator=(logger&& other) NOEXCEPT;
                ~logger();

                void debug(const std::string& message) const;
                void error(const std::string& message) const;
                void info(const std::string& message) const;
                void warn(const std::string& message) const;

            private:
                logger();

                class impl;
                impl* impl_;
            };
        }

        namespace runtime
        {
            class VITA_CORE_API_CPP platform
            {
            public:
                static std::wstring get_current_executable_full_path();
                static std::string get_current_executable_full_path_in_utf8();
                static std::string get_current_executable_version();
                static std::string get_machine_id();
                static std::string get_machine_manufacturer();
                static std::string get_machine_serial_number();
                static std::string get_os_version();
                static std::wstring get_temp_path();
            };

            namespace ipcchannel
            {
                class VITA_CORE_API_CPP client : public ivita_core_runtime_ipcchannel_client
                {
                public:
                    static client& get_instance();

                    client(const client& other);
                    client(client&& other) NOEXCEPT;
                    client& operator=(const client& other);
                    client& operator=(client&& other) NOEXCEPT;
                    ~client();

                    bool is_ready() const;
                    std::wstring request(const std::wstring& input) const;
                    bool set_name(const std::string& name) const;

                private:
                    client();

                    class impl;
                    impl* impl_;
                };
            }

            class VITA_CORE_API_CPP processmanager
            {
            public:
                static unsigned int get_current_process_id();
                static std::wstring get_current_process_name();
            };
        }

        namespace util
        {
            class VITA_CORE_API_CPP convert
            {
            public:
                static std::string to_hex_string(
                        const unsigned char* input,
                        size_t size
                );
                static std::wstring utf8_string_to_wstring(const std::string& input);
                static std::string wstring_to_utf8_string(const std::wstring& input);
            };
        }
    }
}
