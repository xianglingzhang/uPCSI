
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

####################################################################################

set(ENABLE_BITPOLYMUL     ON)
set(ENABLE_SIMPLESTOT     ON)
set(ENABLE_SIMPLESTOT_ASM OFF)
set(ENABLE_MR             ON)
set(ENABLE_MR_KYBER       ON)
set(ENABLE_NP             ON)
set(ENABLE_KOS            ON)
set(ENABLE_IKNP           ON)
set(ENABLE_SILENTOT       ON)
set(ENABLE_DELTA_KOS      ON)
set(ENABLE_DELTA_IKNP     ON)
set(ENABLE_OOS            ON)
set(ENABLE_KKRT           ON)
set(ENABLE_RR             ON)
set(ENABLE_AKN            ON)
set(ENABLE_SILENT_VOLE    )

find_package(cryptoTools REQUIRED HINTS "${CMAKE_CURRENT_LIST_DIR}/.." ${CMAKE_CURRENT_LIST_DIR})

include("${CMAKE_CURRENT_LIST_DIR}/libOTeDepHelper.cmake")


include("${CMAKE_CURRENT_LIST_DIR}/libOTeTargets.cmake")
