#   ./CMakeLists.txt
cmake_minimum_required( VERSION 4.0 )
project( Lumina LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if( BUILD_SERVER_ONLY )
    add_subdirectory( src/common )
    add_subdirectory( src/server )
    return()
elseif( BUILD_CLIENT_ONLY )
    add_subdirectory( src/common )
    add_subdirectory( src/client )
else()
    add_subdirectory( src/common )
    add_subdirectory( src/client )
    add_subdirectory( src/server )
endif()
