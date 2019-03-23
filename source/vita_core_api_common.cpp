#include <codecvt>

#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/spdlog.h"
#include "vita_core_api.hpp"

namespace vita
{
    namespace core
    {
        namespace log
        {
            class logger::impl
            {
            public:
                std::shared_ptr<spdlog::logger> internal_logger;
            };

            logger::logger() : impl_(new impl)
            {
            }

            logger::logger(const logger& other)
            {
                if (&other == this)
                {
                    return;
                }
                impl_ = other.impl_;
            }

            logger::logger(logger&& other) NOEXCEPT
            {
                impl_ = other.impl_;
                other.impl_ = nullptr;
            }

            logger& logger::operator=(const logger& other)
            {
                if (&other == this)
                {
                    return *this;
                }
                impl_ = other.impl_;
                return *this;
            }

            logger& logger::operator=(logger&& other) NOEXCEPT
            {
                if (this != &other)
                {
                    delete impl_;
                    impl_ = other.impl_;
                    other.impl_ = nullptr;
                }
                return *this;
            }

            logger::~logger()
            {
                delete impl_;
            }

            void logger::debug(const std::string& message) const
            {
                impl_->internal_logger->debug(message);
            }

            void logger::error(const std::string& message) const
            {
                impl_->internal_logger->error(message);
            }

            logger& logger::get_instance()
            {
                static logger instance;
                if (instance.impl_->internal_logger == nullptr)
                {
                    const auto process_id = runtime::processmanager::get_current_process_id();
                    const auto process_name = runtime::processmanager::get_current_process_name();
                    const auto log_dir_path = runtime::platform::get_temp_path();
                    const auto log_file_name = L"vita_core_api-" + std::to_wstring(process_id) + L"_" + process_name + L".log";
                    const auto log_path = log_dir_path + L"\\" + log_file_name;
                    instance.impl_->internal_logger = spdlog::rotating_logger_mt(
                            "vita_core_api",
                            log_path,
                            1048576 * 5,
                            3
                    );

                    const auto log_level = config::config::get_instance().get(L"vita_core_api-" + process_name, L"");
                    if (log_level == L"critical")
                    {
                        instance.impl_->internal_logger->set_level(spdlog::level::critical);
                    }
                    else if (log_level == L"debug")
                    {
                        instance.impl_->internal_logger->set_level(spdlog::level::debug);
                    }
                    else if (log_level == L"error")
                    {
                        instance.impl_->internal_logger->set_level(spdlog::level::err);
                    }
                    else if (log_level == L"info")
                    {
                        instance.impl_->internal_logger->set_level(spdlog::level::info);
                    }

                    instance.impl_->internal_logger->critical("==== log level: " + std::string(to_short_c_str(instance.impl_->internal_logger->level())) + " ====");
                    instance.impl_->internal_logger->info("process id: " + std::to_string(process_id));
                    instance.impl_->internal_logger->info("process name: " + util::convert::wstring_to_utf8_string(process_name));
                }
                return instance;
            }

            void logger::info(const std::string& message) const
            {
                impl_->internal_logger->info(message);
            }

            void logger::warn(const std::string& message) const
            {
                impl_->internal_logger->warn(message);
            }
        }

        namespace util
        {
            std::string convert::to_hex_string(
                    const unsigned char* input,
                    const size_t size)
            {
                std::string result;
                char hex_digits[] = "0123456789abcdef";
                for (size_t i = 0; i < size; i++)
                {
                    result += hex_digits[input[i] >> 4];
                    result += hex_digits[input[i] & 0xf];
                }
                return result;
            }

            std::wstring convert::utf8_string_to_wstring(const std::string& input)
            {
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                return converter.from_bytes(input);
            }

            std::string convert::wstring_to_utf8_string(const std::wstring& input)
            {
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                return converter.to_bytes(input);
            }
        }
    }
}

ivita_core_runtime_ipcchannel_client* vita_core_runtime_ipcchannel_client()
{
    return &vita::core::runtime::ipcchannel::client::get_instance();
}

int vita_core_runtime_ipcchannel_client_is_ready()
{
    const auto success = vita::core::runtime::ipcchannel::client::get_instance().is_ready();
    if (success)
    {
        return 1;
    }
    return 0;
}

size_t vita_core_runtime_ipcchannel_client_request(
        const wchar_t* input,
        wchar_t* output,
        const size_t count)
{
    auto result = vita::core::runtime::ipcchannel::client::get_instance().request(input);
    const auto result_array = result.c_str();
    const auto result_array_size = result.length() + 1; // null terminated
    const auto size = count < result_array_size ? count : result_array_size;
    for (size_t i = 0; i < size; i++)
    {
        if (i == size - 1)
        {
            output[i] = L'\0';
        }
        else
        {
            output[i] = result_array[i];
        }
    }
    return result_array_size;
}

int vita_core_runtime_ipcchannel_client_set_name(const char* name)
{
    const auto success = vita::core::runtime::ipcchannel::client::get_instance().set_name(name);
    if (success)
    {
        return 1;
    }
    return 0;
}
