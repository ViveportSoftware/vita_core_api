#define CATCH_CONFIG_MAIN

#include <iostream>

#include "catch.hpp"
#include "vita_core_api.h"
#include "vita_core_api.hpp"

TEST_CASE("OS version is present", "[platform]") {
    const auto version = vita::core::runtime::platform::get_os_version();
    std::cout << "operating system version: \"" << version << "\"" << std::endl;
    REQUIRE(!version.empty());
}

TEST_CASE("File version is set", "[platform]") {
    const auto version = vita::core::runtime::platform::get_current_executable_version();
    std::cout << "main executable version: \"" << version << "\"" << std::endl;
    REQUIRE(!version.empty());
}

TEST_CASE("IPC Channel name is set", "[ipcchannel]") {
    const auto pipe_name = "VitaCoreApiIpcChannelTest";
    REQUIRE(vita_core_runtime_ipcchannel_client_set_name(pipe_name));
}

TEST_CASE("IPC Channel is ready", "[ipcchannel]") {
    const auto pipe_name = "VitaCoreApiIpcChannelTest";
    REQUIRE(vita_core_runtime_ipcchannel_client_set_name(pipe_name));

    REQUIRE(vita_core_runtime_ipcchannel_client_is_ready());
}

TEST_CASE("IPC request is sent", "[ipcchannel]") {
    const auto pipe_name = "VitaCoreApiIpcChannelTest";
    REQUIRE(vita_core_runtime_ipcchannel_client_set_name(pipe_name));

    REQUIRE(vita_core_runtime_ipcchannel_client_is_ready());

    std::wstring input = L"123測試123čřžýáí";
    const size_t output_buffer_size = 13;
    auto output = new wchar_t[output_buffer_size];
    const auto count1 = vita_core_runtime_ipcchannel_client_request(
            input.c_str(),
            output,
            output_buffer_size
    );
    REQUIRE(count1 > 0);

    auto output_size = std::min(count1, output_buffer_size);
    if (count1 <= output_buffer_size)
    {
        std::wcout << "Output size: " << output_size << ", data: \"" << std::wstring(output) << "\"" << std::endl;
    }
    else
    {
        std::wcout << "Output (1st-pass) size: " << output_size << ", data: \"" << std::wstring(output) << "\"" << std::endl;
        delete[] output;
        output = new wchar_t[count1];
        const auto count2 = vita_core_runtime_ipcchannel_client_request(
            input.c_str(),
            output,
            count1
        );
        REQUIRE(count2 > 0);

        output_size = std::min(count2, count1);
        std::wcout << "Output (2nd-pass) size: " << output_size << ", data: \"" << std::wstring(output) << "\"" << std::endl;
    }
    delete[] output;
}
