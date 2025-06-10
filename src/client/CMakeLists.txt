project( lumina_client_project )

find_package( Qt6 REQUIRED COMPONENTS Core Gui Widgets Network )

set( CMAKE_AUTOMOC ON )
set( CMAKE_AUTORCC ON )

add_executable( lumina_client 
    main_client.cpp
    AuthWindow.cpp
    RestoreDialog.cpp
#   resources
    resources/resources.qrc
)

target_link_libraries( lumina_client
    Qt::Core
    Qt::Gui
    Qt::Widgets
    Qt::Network
)
