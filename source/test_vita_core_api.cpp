﻿#define CATCH_CONFIG_MAIN

#include <iostream>

#include "catch.hpp"
#include "vita_core_api.h"
#include "vita_core_api.hpp"

TEST_CASE("Machine ID is present", "[platform]") {
    const auto machine_id = vita::core::runtime::platform::get_machine_id();
    std::cout << "machine id: \"" << machine_id << "\"" << std::endl;
    REQUIRE(!machine_id.empty());
}

TEST_CASE("Machine manufacturer is present", "[platform]") {
    const auto machine_manufacturer = vita::core::runtime::platform::get_machine_manufacturer();
    std::cout << "machine manufacturer: \"" << machine_manufacturer << "\"" << std::endl;
    REQUIRE(!machine_manufacturer.empty());
}

TEST_CASE("Machine serial number is present", "[platform]") {
    const auto machine_serial_number = vita::core::runtime::platform::get_machine_serial_number();
    std::cout << "machine serial number: \"" << machine_serial_number << "\"" << std::endl;
    REQUIRE(!machine_serial_number.empty());
}

TEST_CASE("OS version is present", "[platform]") {
    const auto version = vita::core::runtime::platform::get_os_version();
    std::cout << "operating system version: \"" << version << "\"" << std::endl;
    REQUIRE(!version.empty());
}

TEST_CASE("File path is present", "[platform]") {
    const auto full_path = vita::core::runtime::platform::get_current_executable_full_path();
    std::wcout << "main executable full path: \"" << full_path << "\"" << std::endl;
    REQUIRE(!full_path.empty());
    const auto full_path_exist = vita::core::io::file::exist(full_path);
    REQUIRE(full_path_exist);
    const auto is_valid = vita::core::io::directory::is_valid_and_writable(full_path);
    REQUIRE(is_valid);
    const auto full_path_in_utf8 = vita::core::runtime::platform::get_current_executable_full_path_in_utf8();
    std::cout << "main executable full path in utf8: \"" << full_path_in_utf8 << "\"" << std::endl;
    REQUIRE(!full_path_in_utf8.empty());
    const auto full_path_in_utf8_exist = vita::core::io::file::exist(full_path_in_utf8);
    REQUIRE(full_path_in_utf8_exist);
    const auto is_valid_in_utf8 = vita::core::io::directory::is_valid_and_writable(full_path_in_utf8);
    REQUIRE(is_valid_in_utf8);
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

    REQUIRE(vita_core_runtime_ipcchannel_client_is_ready_ex(pipe_name));

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

    auto output_ex = new wchar_t[output_buffer_size];
    const auto count1_ex = vita_core_runtime_ipcchannel_client_request_ex(
            pipe_name,
            input.c_str(),
            output_ex,
            output_buffer_size
    );
    REQUIRE(count1_ex > 0);

    auto output_ex_size = std::min(count1_ex, output_buffer_size);
    if (count1_ex <= output_buffer_size)
    {
        std::wcout << "Output size: " << output_ex_size << ", data: \"" << std::wstring(output_ex) << "\"" << std::endl;
    }
    else
    {
        std::wcout << "Output (1st-pass) size: " << output_ex_size << ", data: \"" << std::wstring(output_ex) << "\"" << std::endl;
        delete[] output_ex;
        output_ex = new wchar_t[count1_ex];
        const auto count2_ex = vita_core_runtime_ipcchannel_client_request_ex(
                pipe_name,
                input.c_str(),
                output_ex,
                count1_ex
        );
        REQUIRE(count2_ex > 0);

        output_size = std::min(count2_ex, count1_ex);
        std::wcout << "Output (2nd-pass) size: " << output_ex_size << ", data: \"" << std::wstring(output_ex) << "\"" << std::endl;
    }
    delete[] output_ex;
}
