#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleAut32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wbemuuid.lib")

#include <codecvt>
#include <iostream>
#include <sstream>

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <wbemidl.h>

#include "vita_core_api.hpp"

//+ forward declaration
LONG registry_get_dword_value(
        HKEY registry_key,
        const std::wstring& value_name,
        DWORD& value,
        DWORD default_value
);
LONG registry_get_string_value(
        HKEY registry_key,
        const std::wstring& value_name,
        std::wstring& value,
        const std::wstring& default_value
);
std::string wmi_get_string_value(
        const std::wstring& wmi_namespace,
        const std::wstring& query_language,
        const std::wstring& query_string,
        const std::wstring& property_name
);
//- forward declaration

namespace vita
{
    namespace core
    {
        namespace config
        {
            class config::impl
            {
            };

            config::config() : impl_(new impl)
            {
            }

            config::config(const config& other)
            {
                if (&other == this)
                {
                    return;
                }
                impl_ = other.impl_;
            }

            config::config(config&& other) NOEXCEPT
            {
                impl_ = other.impl_;
                other.impl_ = nullptr;
            }

            config& config::operator=(const config& other)
            {
                if (&other == this)
                {
                    return *this;
                }
                impl_ = other.impl_;
                return *this;
            }

            config& config::operator=(config&& other) NOEXCEPT
            {
                if (this != &other)
                {
                    delete impl_;
                    impl_ = other.impl_;
                    other.impl_ = nullptr;
                }
                return *this;
            }

            config::~config()
            {
                delete impl_;
            }

            std::wstring config::get(
                    const std::wstring& value_name,
                    const std::wstring& default_value) const
            {
                std::wstring registry_base_key = L"SOFTWARE\\HTC\\Vita\\Config";
                std::wstring result;
                HKEY registry_key;
                auto status = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        registry_base_key.c_str(),
                        0,
                        KEY_READ | KEY_WOW64_64KEY,
                        &registry_key
                );
                if (status == ERROR_SUCCESS)
                {
                    status = registry_get_string_value(
                            registry_key,
                            value_name,
                            result,
                            default_value
                    );
                    if (status == ERROR_SUCCESS)
                    {
                        return result;
                    }
                }

                status = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        registry_base_key.c_str(),
                        0,
                        KEY_READ | KEY_WOW64_32KEY,
                        &registry_key
                );
                if (status == ERROR_SUCCESS)
                {
                    status = registry_get_string_value(
                            registry_key,
                            value_name,
                            result,
                            default_value
                    );
                    if (status == ERROR_SUCCESS)
                    {
                        return result;
                    }
                }

                return default_value;
            }

            config& config::get_instance()
            {
                static config instance;
                return instance;
            }
        }

        namespace crypto
        {
            std::string sha1::generate_from_utf8_string_in_hex(const std::string& utf8_string)
            {
                HCRYPTPROV crypto_provider_handle = 0;
                HCRYPTHASH crypto_hash_handle = 0;
                auto success = CryptAcquireContext(
                        &crypto_provider_handle,
                        nullptr,
                        nullptr,
                        PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT
                );
                if (!success)
                {
                    log::logger::get_instance().error("can not acquire crypto context. GLE=" + std::to_string(GetLastError()));
                    return "";
                }

                success = CryptCreateHash(
                        crypto_provider_handle,
                        CALG_SHA1,
                        0,
                        0,
                        &crypto_hash_handle
                );
                if (!success)
                {
                    log::logger::get_instance().error("can not create crypto sha1 hash. GLE=" + std::to_string(GetLastError()));
                    CryptReleaseContext(
                            crypto_provider_handle,
                            0
                    );
                    return "";
                }

                success = CryptHashData(
                        crypto_hash_handle,
                        reinterpret_cast<const BYTE*>(utf8_string.data()),
                        static_cast<DWORD>(utf8_string.length()),
                        0
                );
                if (!success)
                {
                    log::logger::get_instance().error("can not insert crypto hash data. GLE=" + std::to_string(GetLastError()));
                    CryptDestroyHash(crypto_hash_handle);
                    CryptReleaseContext(
                            crypto_provider_handle,
                            0
                    );
                    return "";
                }

                const DWORD sha1_hash_length_in_byte = 20; // 160-bit for SHA-1
                auto byte_to_write = sha1_hash_length_in_byte;
                unsigned char digest[sha1_hash_length_in_byte];
                success = CryptGetHashParam(
                        crypto_hash_handle,
                        HP_HASHVAL,
                        digest,
                        &byte_to_write,
                        0
                );
                if (!success)
                {
                    log::logger::get_instance().error("can not compute crypto hash. GLE=" + std::to_string(GetLastError()));
                    CryptDestroyHash(crypto_hash_handle);
                    CryptReleaseContext(
                            crypto_provider_handle,
                            0
                    );
                    return "";
                }

                return util::convert::to_hex_string(
                        digest,
                        byte_to_write
                );
            }
        }

        namespace io
        {
            bool directory::is_valid_and_writable(const std::wstring& path)
            {
                const auto ret = _waccess_s(path.c_str(), /* write */ 2) == 0;
                return ret;
            }

            bool directory::is_valid_and_writable(const std::string& path_in_utf8)
            {
                auto path = util::convert::utf8_string_to_wstring(path_in_utf8);
                const auto ret = _waccess_s(path.c_str(), /* write */ 2) == 0;
                return ret;
            }

            bool file::exist(const std::wstring& file)
            {
                return PathFileExistsW(file.c_str()) != 0;
            }

            bool file::exist(const std::string& file_in_utf8)
            {
                auto file = util::convert::utf8_string_to_wstring(file_in_utf8);
                return PathFileExistsW(file.c_str()) != 0;
            }
        }

        namespace runtime
        {
            namespace ipcchannel
            {
                class client::impl
                {
                public:
                    std::wstring get_wide_name() const;
                    bool set_name(const std::string& name);

                    std::wstring name;
                };

                std::wstring client::impl::get_wide_name() const
                {
                    return name;
                }

                bool client::impl::set_name(const std::string& name)
                {
                    if (!name.empty())
                    {
                        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                        this->name.assign(converter.from_bytes(name));
                    }
                    return true;
                }

                client::client() : impl_(new impl)
                {
                }

                client::client(const client& other) : impl_(other.impl_)
                {
                }

                client::client(client&& other) NOEXCEPT
                {
                    impl_ = other.impl_;
                    other.impl_ = nullptr;
                }

                client& client::operator=(const client& other)
                {
                    if (&other == this)
                    {
                        return *this;
                    }
                    impl_ = other.impl_;
                    return *this;
                }

                client& client::operator=(client&& other) NOEXCEPT
                {
                    if (this != &other)
                    {
                        delete impl_;
                        impl_ = other.impl_;
                        other.impl_ = nullptr;
                    }
                    return *this;
                }

                client::~client()
                {
                    delete impl_;
                }

                client& client::get_instance()
                {
                    static client instance;
                    return instance;
                }

                bool client::is_ready() const
                {
                    const auto pipe_name = impl_->get_wide_name();

                    const auto pipe_handle = CreateFileW(
                            pipe_name.c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                    );
                    if (pipe_handle == INVALID_HANDLE_VALUE)
                    {
                        log::logger::get_instance().error("pipe handle is not valid");
                        if (GetLastError() != ERROR_PIPE_BUSY)
                        {
                            log::logger::get_instance().error("can not open pipe. GLE=" + std::to_string(GetLastError()));
                        }
                        return false;
                    }

                    if (!WaitNamedPipeW(pipe_name.c_str(), 100))
                    {
                        log::logger::get_instance().error("can not open pipe in wait timeout. GLE=" + std::to_string(GetLastError()));
                        return false;
                    }

                    DWORD read_mode = PIPE_READMODE_MESSAGE;
                    auto success = SetNamedPipeHandleState(
                            pipe_handle,
                            &read_mode,
                            nullptr,
                            nullptr
                    );
                    if (!success)
                    {
                        log::logger::get_instance().error("can not set named pipe handle state. GLE=" + std::to_string(GetLastError()));
                        CloseHandle(pipe_handle);
                        return false;
                    }

                    auto utf8_input = util::convert::wstring_to_utf8_string(L"");
                    const auto message_to_send = utf8_input.c_str();
                    const auto bytes_to_write = static_cast<DWORD>((std::strlen(message_to_send) + 1) * sizeof(char));  // NOLINT

                    DWORD bytes_written = 0;
                    log::logger::get_instance().debug("sending " + std::to_string(bytes_to_write) + " byte message: \"" + message_to_send + "\"");
                    success = WriteFile(
                            pipe_handle,
                            message_to_send,
                            bytes_to_write,
                            &bytes_written,
                            nullptr
                    );
                    if (!success)
                    {
                        log::logger::get_instance().error("can not write message to pipe. GLE=" + std::to_string(GetLastError()));
                        CloseHandle(pipe_handle);
                        return false;
                    }

                    std::stringstream message_received;
                    const auto buffer_size = 512;
                    char buffer_to_write[buffer_size];
                    DWORD bytes_read = 0;
                    do
                    {
                        success = ReadFile(
                                pipe_handle,
                                buffer_to_write,
                                buffer_size * sizeof(char),
                                &bytes_read,
                                nullptr
                        );

                        if (!success && GetLastError() != ERROR_MORE_DATA)
                        {
                            break;
                        }
                        message_received << std::string(buffer_to_write, bytes_read);
                    } while (!success);

                    CloseHandle(pipe_handle);
                    return true;
                }

                std::wstring client::request(const std::wstring& input) const
                {
                    const auto pipe_name = impl_->get_wide_name();

                    const auto pipe_handle = CreateFileW(
                            pipe_name.c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                    );
                    if (pipe_handle == INVALID_HANDLE_VALUE)
                    {
                        std::cout << "pipe handle is not valid" << std::endl;
                        if (GetLastError() != ERROR_PIPE_BUSY)
                        {
                            log::logger::get_instance().error("can not open pipe. GLE=" + std::to_string(GetLastError()));
                        }
                        return L"";
                    }

                    DWORD read_mode = PIPE_READMODE_MESSAGE;
                    auto success = SetNamedPipeHandleState(
                            pipe_handle,
                            &read_mode,
                            nullptr,
                            nullptr
                    );
                    if (!success)
                    {
                        log::logger::get_instance().error("can not set named pipe handle state. GLE=" + std::to_string(GetLastError()));
                        CloseHandle(pipe_handle);
                        return L"";
                    }

                    auto utf8_input = util::convert::wstring_to_utf8_string(input);
                    const auto message_to_send = utf8_input.c_str();
                    const auto bytes_to_write = static_cast<DWORD>((std::strlen(message_to_send) + 1) * sizeof(char));  // NOLINT

                    DWORD bytes_written = 0;
                    log::logger::get_instance().debug("sending " + std::to_string(bytes_to_write) + " byte message: \"" + message_to_send + "\"");
                    success = WriteFile(
                            pipe_handle,
                            message_to_send,
                            bytes_to_write,
                            &bytes_written,
                            nullptr
                    );
                    if (!success)
                    {
                        log::logger::get_instance().error("can not write message to pipe. GLE=" + std::to_string(GetLastError()));
                        CloseHandle(pipe_handle);
                        return L"";
                    }

                    std::stringstream message_received;
                    const auto buffer_size = 512;
                    char buffer_to_write[buffer_size];
                    DWORD bytes_read = 0;
                    do
                    {
                        success = ReadFile(
                                pipe_handle,
                                buffer_to_write,
                                buffer_size * sizeof(char),
                                &bytes_read,
                                nullptr
                        );

                        if (!success && GetLastError() != ERROR_MORE_DATA)
                        {
                            break;
                        }
                        message_received << std::string(buffer_to_write, bytes_read);
                    } while (!success);

                    CloseHandle(pipe_handle);
                    auto output = util::convert::utf8_string_to_wstring(std::string(message_received.str()));
                    return output;
                }

                bool client::set_name(const std::string& name) const
                {
                    const auto name_in_hex = crypto::sha1::generate_from_utf8_string_in_hex(name);
                    return impl_->set_name(R"(\\.\pipe\)" + name_in_hex);
                }
            }

            std::wstring platform::get_current_executable_full_path()
            {
                const auto file_path_size = MAX_PATH + 1;
                wchar_t buffer[file_path_size];
                GetModuleFileName(
                        nullptr,
                        buffer,
                        file_path_size
                );

                std::wstring file_path = buffer;
                return file_path;
            }

            std::string platform::get_current_executable_full_path_in_utf8()
            {
                const auto file_path_size = MAX_PATH + 1;
                wchar_t file_path[file_path_size];
                GetModuleFileNameW(
                        nullptr,
                        file_path,
                        file_path_size
                );
                const auto file_path_wstring = std::wstring(file_path);
                auto file_path_string_in_utf8 = util::convert::wstring_to_utf8_string(file_path_wstring);
                return file_path_string_in_utf8;
            }

            std::string platform::get_current_executable_version()
            {
                std::string result;

                const auto file_path_size = MAX_PATH + 1;
                wchar_t file_path[file_path_size];
                GetModuleFileNameW(
                        nullptr,
                        file_path,
                        file_path_size
                );

                DWORD version_handle = 0;
                const auto version_info_size = GetFileVersionInfoSizeW(file_path, &version_handle);
                if (version_info_size > 0)
                {
                    const auto version_info_data = new char[version_info_size];
                    if (GetFileVersionInfoW(file_path, version_handle, version_info_size, version_info_data))
                    {
                        LPBYTE version_info_buffer = nullptr;
                        UINT version_info_buffer_size = 0;
                        if (VerQueryValueW(version_info_data, L"\\", reinterpret_cast<LPVOID*>(&version_info_buffer), &version_info_buffer_size))
                        {
                            if (version_info_buffer_size > 0)
                            {
                                const auto version_info = reinterpret_cast<VS_FIXEDFILEINFO *>(version_info_buffer);
                                char version_buffer[100];
                                _snprintf_s(version_buffer, 100, "%d.%d.%d.%d",
                                        (version_info->dwFileVersionMS >> 16) & 0xffff,
                                        (version_info->dwFileVersionMS >> 0) & 0xffff,
                                        (version_info->dwFileVersionLS >> 16) & 0xffff,
                                        (version_info->dwFileVersionLS >> 0) & 0xffff
                                );
                                result = version_buffer;
                            }
                        }
                    }
                    delete[] version_info_data;
                }

                return result;
            }

            std::string platform::get_machine_id()
            {
                std::wstring registry_base_key = L"SOFTWARE\\Microsoft\\Cryptography";
                std::string result;
                HKEY registry_key;
                auto status = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        registry_base_key.c_str(),
                        0,
                        KEY_READ | KEY_WOW64_64KEY,
                        &registry_key
                );
                if (status != ERROR_SUCCESS)
                {
                    status = RegOpenKeyExW(
                            HKEY_LOCAL_MACHINE,
                            registry_base_key.c_str(),
                            0,
                            KEY_READ | KEY_WOW64_32KEY,
                            &registry_key
                    );
                }
                if (status != ERROR_SUCCESS)
                {
                    return result;
                }

                std::wstring value;
                registry_get_string_value(
                        registry_key,
                        L"MachineGuid",
                        value,
                        L"bad"
                );
                result = util::convert::wstring_to_utf8_string(value);
                return result;
            }

            std::string platform::get_machine_manufacturer()
            {
                const std::wstring wmi_namespace = L"root\\cimv2";
                const std::wstring wmi_query_language = L"WQL";
                const std::wstring wmi_query_string = L"Select * from Win32_OperatingSystem";
                const std::wstring wmi_property_name = L"Manufacturer";
                auto result = wmi_get_string_value(
                        wmi_namespace,
                        wmi_query_language,
                        wmi_query_string,
                        wmi_property_name
                );
                if (result.empty())
                {
                    result = "Microsoft Corporation";
                }
                return result;
            }

            std::string platform::get_machine_serial_number()
            {
                const std::wstring wmi_namespace = L"root\\cimv2";
                const std::wstring wmi_query_language = L"WQL";
                const std::wstring wmi_query_string = L"SELECT * FROM Win32_ComputerSystemProduct";
                const std::wstring wmi_property_name = L"UUID";
                auto result = wmi_get_string_value(
                        wmi_namespace,
                        wmi_query_language,
                        wmi_query_string,
                        wmi_property_name
                );
                if (result.empty())
                {
                    result = get_machine_id();
                }
                return result;
            }

            std::string platform::get_os_version()
            {
                std::wstring registry_base_key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
                std::string result;
                HKEY registry_key;
                auto status = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        registry_base_key.c_str(),
                        0,
                        KEY_READ | KEY_WOW64_64KEY,
                        &registry_key
                );
                if (status != ERROR_SUCCESS)
                {
                    status = RegOpenKeyExW(
                            HKEY_LOCAL_MACHINE,
                            registry_base_key.c_str(),
                            0,
                            KEY_READ | KEY_WOW64_32KEY,
                            &registry_key
                    );
                }
                if (status != ERROR_SUCCESS)
                {
                    return result;
                }

                std::wstring value;
                registry_get_string_value(
                        registry_key,
                        L"CurrentBuildNumber",
                        value,
                        L"0"
                );
                auto current_build_number = util::convert::wstring_to_utf8_string(value);

                DWORD major_version = 0;
                DWORD minor_version = 0;
                registry_get_dword_value(
                        registry_key,
                        L"CurrentMajorVersionNumber",
                        major_version,
                        0
                );
                registry_get_dword_value(
                        registry_key,
                        L"CurrentMinorVersionNumber",
                        minor_version,
                        0
                );
                if (major_version == 0)
                {
                    registry_get_string_value(
                            registry_key,
                            L"CurrentVersion",
                            value,
                            L"0"
                    );
                    auto current_version = util::convert::wstring_to_utf8_string(value);
                    char version_buffer[100];
                    snprintf(
                            version_buffer,
                            sizeof(version_buffer),
                            "%s.%s",
                            current_version.c_str(),
                            current_build_number.c_str()
                    );
                    result = version_buffer;
                }
                else
                {
                    char version_buffer[100];
                    snprintf(
                            version_buffer,
                            sizeof(version_buffer),
                            "%lu.%lu.%s",
                            major_version,
                            minor_version,
                            current_build_number.c_str()
                    );
                    result = version_buffer;
                }

                return result;
            }

            std::wstring platform::get_temp_path()
            {
                const auto file_path_size = MAX_PATH + 1;
                wchar_t temp_path[file_path_size];
                const auto size = GetEnvironmentVariableW(
                        L"TEMP",
                        temp_path,
                        sizeof temp_path
                );
                if (size <= 0)
                {
                    return std::wstring(L"");
                }
                return std::wstring(temp_path, size);
            }

            unsigned int processmanager::get_current_process_id()
            {
                return GetCurrentProcessId();
            }

            std::wstring processmanager::get_current_process_name()
            {
                const auto process_handle = GetCurrentProcess();
                const auto file_path_size = MAX_PATH + 1;
                wchar_t file_name[file_path_size];
                const auto size = GetModuleBaseNameW(
                        process_handle,
                        nullptr,
                        file_name,
                        sizeof file_name
                );
                if (size <= 0)
                {
                    return std::wstring(L"UNKNOWN_PROCESS");
                }
                return std::wstring(file_name, size);
            }
        }
    }
}

LONG registry_get_dword_value(
        const HKEY registry_key,
        const std::wstring& value_name,
        DWORD& value,
        const DWORD default_value)
{
    value = default_value;
    DWORD registry_value_type;
    DWORD buffer_size = sizeof(DWORD);
    DWORD result = 0;
    const auto status = RegQueryValueExW(
            registry_key,
            value_name.c_str(),
            nullptr,
            &registry_value_type,
            reinterpret_cast<LPBYTE>(&result),
            &buffer_size
    );
    if (status == ERROR_SUCCESS && registry_value_type == REG_DWORD)
    {
        value = result;
    }
    return status;
}

LONG registry_get_string_value(
        const HKEY registry_key,
        const std::wstring& value_name,
        std::wstring& value,
        const std::wstring& default_value)
{
    value = default_value;
    const DWORD default_registry_value_data_size = 32;
    DWORD registry_value_type;
    auto registry_value_data = new wchar_t[default_registry_value_data_size];
    DWORD registry_value_data_length = sizeof registry_value_data;
    auto status = RegQueryValueExW(
            registry_key,
            value_name.c_str(),
            nullptr,
            &registry_value_type,
            reinterpret_cast<LPBYTE>(registry_value_data),
            &registry_value_data_length
    );
    if (status == ERROR_MORE_DATA)
    {
        delete[] registry_value_data;
        registry_value_data = new wchar_t[registry_value_data_length];
        status = RegQueryValueExW(
                registry_key,
                value_name.c_str(),
                nullptr,
                &registry_value_type,
                reinterpret_cast<LPBYTE>(registry_value_data),
                &registry_value_data_length
        );
    }
    if (status == ERROR_SUCCESS && registry_value_type == REG_SZ)
    {
        value = registry_value_data;
    }
    return status;
}

std::string wmi_get_string_value(
        const std::wstring& wmi_namespace,
        const std::wstring& query_language,
        const std::wstring& query_string,
        const std::wstring& property_name)
{
    std::string result;
    auto status = CoInitializeEx(
            nullptr,
            COINIT_MULTITHREADED
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not initialize com component. status=" + std::to_string(status));
        return result;
    }

    status = CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not initialize com security. status=" + std::to_string(status));
        CoUninitialize();
        return result;
    }

    IWbemLocator* locator = nullptr;
    status = CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<LPVOID*>(&locator)
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not create wbem locator. status=" + std::to_string(status));
        CoUninitialize();
        return result;
    }

    IWbemServices* services = nullptr;
    status = locator->ConnectServer(
            BSTR(wmi_namespace.c_str()),
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &services
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not connect wbem services. status=" + std::to_string(status));
        locator->Release();
        CoUninitialize();
        return result;
    }

    status = CoSetProxyBlanket(
            services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not set proxy blanket. status=" + std::to_string(status));
        services->Release();
        locator->Release();
        CoUninitialize();
        return result;
    }

    IEnumWbemClassObject* class_object_enumerator = nullptr;
    status = services->ExecQuery(
            BSTR(query_language.c_str()),
            BSTR(query_string.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &class_object_enumerator
    );
    if (FAILED(status))
    {
        vita::core::log::logger::get_instance().error("can not execute query. status=" + std::to_string(status));
        services->Release();
        locator->Release();
        CoUninitialize();
        return result;
    }

    IWbemClassObject* class_object;
    ULONG returned = 0;
    while (class_object_enumerator)
    {
        class_object_enumerator->Next(
                WBEM_INFINITE,
                1,
                &class_object,
                &returned
        );
        if (returned == 0)
        {
            break;
        }

        VARIANT variant;
        class_object->Get(
                property_name.c_str(),
                0,
                &variant,
                nullptr,
                nullptr
        );

        auto temp_in_bstr = variant.bstrVal;
        std::wstring temp(temp_in_bstr, SysStringLen(temp_in_bstr));
        result = vita::core::util::convert::wstring_to_utf8_string(temp);
        VariantClear(&variant);
        class_object->Release();
    }

    services->Release();
    locator->Release();
    CoUninitialize();
    return result;
}
