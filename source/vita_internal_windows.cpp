#include <string>
#include "vita_core_api.hpp"
#include "DllVersionInfo.h"

namespace vita
{
    namespace internal
    {
        std::string binary::get_arch()
        {
            return std::string("Windows ") + std::to_string(sizeof(void*) * 8) + "-bit";
        }

        std::string binary::get_version()
        {
            const auto version = FILE_VERSION_RESOURCE_STR;
            return std::string(version);
        }
    }
}
