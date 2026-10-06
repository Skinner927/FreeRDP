set(MODULE_NAME "TestSmartCard")
set(MODULE_PREFIX "TEST_SMARTCARD")

disable_warnings_for_directory(${CMAKE_CURRENT_BINARY_DIR})

set(${MODULE_PREFIX}_DRIVER ${MODULE_NAME}.c)

set(${MODULE_PREFIX}_TESTS TestSmartCardListReaders.c)

if(WITH_SMARTCARD_PCSC)
  list(APPEND ${MODULE_PREFIX}_TESTS TestSmartCardPcscTransaction.c)
endif()

create_test_sourcelist(${MODULE_PREFIX}_SRCS ${${MODULE_PREFIX}_DRIVER} ${${MODULE_PREFIX}_TESTS})

add_executable(${MODULE_NAME} ${${MODULE_PREFIX}_SRCS})

if(WITH_SMARTCARD_PCSC)
  # The transaction emulation is internal to libwinpr, compile it into the test
  target_sources(${MODULE_NAME} PRIVATE ../smartcard_pcsc_transaction.c)
endif()

target_link_libraries(${MODULE_NAME} PRIVATE winpr)

set_target_properties(${MODULE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${TESTING_OUTPUT_DIRECTORY}")

foreach(test ${${MODULE_PREFIX}_TESTS})
  get_filename_component(TestName ${test} NAME_WE)
  add_test(${TestName} ${TESTING_OUTPUT_DIRECTORY}/${MODULE_NAME} ${TestName})
endforeach()

set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "WinPR/Test")
