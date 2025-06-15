#   ./src/common/CMakeLists.txt
project(lumina_common_libs)

find_package( Boost REQUIRED COMPONENTS json )

add_library( lumina_common_libs 
    ConfigManager.cpp
    ValidationUtils.cpp
)

target_include_directories( lumina_common_libs
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries( lumina_common_libs
    Boost::json
)
