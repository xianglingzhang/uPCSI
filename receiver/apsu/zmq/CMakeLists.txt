# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/zmq
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
