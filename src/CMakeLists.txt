find_package(OpenSSL)
find_package(ZLIB)

# OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# zlib
include_directories(${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# libwz.so - shared library
include_directories(.)
add_library(lib SHARED
  byteorder.c
  file.c
  #../tests/mem.c
)
set_target_properties(lib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(lib ${LIBS})
#set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-wrap,malloc -Wl,-wrap,free")
set(CMAKE_C_FLAGS "-Wall -Werror -std=c99 -pedantic -g")

# wz/*.h - headers
install(TARGETS lib DESTINATION lib)
install(
  FILES
  wz.h
  file.h
  DESTINATION include/wz
)

# wz - main program
add_executable(wz main.c)
target_link_libraries(wz lib)
