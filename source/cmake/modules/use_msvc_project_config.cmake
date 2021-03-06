#
#
if( MSVC )
  string(APPEND CMAKE_CXX_FLAGS " /EHsc")
endif()

if( BUILD_WITH_SHARED_VCRT )
  ## Presets:
  ##   Use /MD build instead of /MT to be dependent on msvcrtXXX.dll
  ##   Use /Z7 build instead of /Zi to avoid vcXXX.pdb
  foreach( flag_var
      CMAKE_C_FLAGS
      CMAKE_C_FLAGS_DEBUG
      CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_MINSIZEREL
      CMAKE_C_FLAGS_RELWITHDEBINFO
      CMAKE_CXX_FLAGS
      CMAKE_CXX_FLAGS_DEBUG
      CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_MINSIZEREL
      CMAKE_CXX_FLAGS_RELWITHDEBINFO )
    if( ${flag_var} MATCHES "/MT" )
      string( REGEX REPLACE "/MT" "/MD" ${flag_var} "${${flag_var}}" )
    endif()
  endforeach()
endif()

if( BUILD_WITH_STATIC_VCRT )
  ## Presets:
  ##   Use /MT build instead of /MD to avoid msvcrtXXX.dll
  ##   Use /Z7 build instead of /Zi to avoid vcXXX.pdb
  foreach( flag_var
      CMAKE_C_FLAGS
      CMAKE_C_FLAGS_DEBUG
      CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_MINSIZEREL
      CMAKE_C_FLAGS_RELWITHDEBINFO
      CMAKE_CXX_FLAGS
      CMAKE_CXX_FLAGS_DEBUG
      CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_MINSIZEREL
      CMAKE_CXX_FLAGS_RELWITHDEBINFO )
    if( ${flag_var} MATCHES "/MD" )
      string( REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}" )
    endif()
  endforeach()
endif()

foreach( flag_var
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_MINSIZEREL
    CMAKE_C_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_MINSIZEREL
    CMAKE_CXX_FLAGS_RELWITHDEBINFO )
  if( ${flag_var} MATCHES "/Zi" )
    string( REGEX REPLACE "/Zi" "/Z7" ${flag_var} "${${flag_var}}" )
  endif()
endforeach()
