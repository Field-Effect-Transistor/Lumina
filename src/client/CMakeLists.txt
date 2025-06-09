project( lumina_client_project )

find_package( Qt6 REQUIRED COMPONENTS Core Gui Widgets Network )

add_executable( lumina_client 
    main_client.cpp
)

target_link_libraries( lumina_client
    Qt::Core
    Qt::Gui
    Qt::Widgets
    Qt::Network
)
