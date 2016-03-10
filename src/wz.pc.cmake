prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@INSTALL_LIBRARY_DIR@
includedir=@INSTALL_INCLUDE_DIR@

Name: wz
Description: wz Reading Library
Version: @VERSION@

Requires:
Libs: -L${libdir} -lwz
Libs.private: -laes256 -lz
Cflags: -I${includedir}
