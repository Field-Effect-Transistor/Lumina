#   ./src/server/CMakeLists.txt
project( lumina_server_project )

find_package( SQLite3 REQUIRED )
find_package( Boost REQUIRED COMPONENTS system thread json process )
find_package( OpenSSL REQUIRED )
find_package( CURL REQUIRED )

add_executable( lumina_server 
    main_server.cpp
    DatabaseManager.cpp
    TlsSession.cpp
    LuminaTlsServer.cpp
    VpnServer.cpp
)

target_link_libraries( lumina_server
    lumina_common_libs
    SQLite::SQLite3
    Boost::system
    Boost::process
    Boost::thread
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)
