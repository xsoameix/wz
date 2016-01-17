find_package(OpenSSL)

# OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# libwz.so - shared library
include_directories(.)
file(GLOB_RECURSE SOURCES *.c)
add_library(lib SHARED ${SOURCES})
set_target_properties(lib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(lib ${LIBS})

# wz/*.h - headers
install(TARGETS lib DESTINATION lib)
install(
  FILES
  wz.h
  file.h
  DESTINATION include/wz
)

# wz - main program
add_executable(wz wz.c)
target_link_libraries(wz lib)
