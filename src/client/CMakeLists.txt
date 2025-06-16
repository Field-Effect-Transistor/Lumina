project( lumina_client_project )

find_package( Qt6 REQUIRED COMPONENTS Core Gui Widgets Network )

set( CMAKE_AUTOMOC ON )
set( CMAKE_AUTORCC ON )

add_executable( lumina_client 
    main_client.cpp
    AuthWindow.cpp
    RestoreDialog.cpp
    LuminaTlsClient.cpp
#   resources
    resources/resources.qrc
)

target_link_libraries( lumina_client
    lumina_common_libs
    Qt::Core
    Qt::Gui
    Qt::Widgets
    Qt::Network
)
