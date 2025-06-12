cmake_minimum_required( VERSION 4.0 )
project( Lumina LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

add_subdirectory( src/client )
add_subdirectory( src/server )
