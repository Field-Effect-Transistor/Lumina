project( lumina_server_project )

find_package( SQLite3 REQUIRED )
find_package( Boost REQUIRED COMPONENTS system thread json )
find_package( OpenSSL REQUIRED )
find_package( CURL REQUIRED )

add_executable( lumina_server 
    main_server.cpp
    ConfigManager.cpp
)

target_link_libraries( lumina_server
    SQLite::SQLite3
    Boost::system
    Boost::thread
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)
