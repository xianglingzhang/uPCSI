# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/plaintext_powers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
${CMAKE_CURRENT_LIST_DIR}/plaintext_powers.cpp
${CMAKE_CURRENT_LIST_DIR}/sender.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/itt.h
        ${CMAKE_CURRENT_LIST_DIR}/match_record.h
        ${CMAKE_CURRENT_LIST_DIR}/sender.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu
)

set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
