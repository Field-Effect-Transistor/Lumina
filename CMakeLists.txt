#   ./CMakeLists.txt
cmake_minimum_required( VERSION 4.0 )
project( Lumina LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Doxygen REQUIRED dot)

if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

    add_custom_target(doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen..."
        VERBATIM
    )
    
    message(STATUS "Doxygen found. To generate documentation, run: make doc (or equivalent)")
endif()

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
