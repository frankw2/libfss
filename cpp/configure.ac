AC_INIT([test_fss], [0.1], [frankw@mit.edu])
AM_INIT_AUTOMAKE([foreign])

LT_INIT
AC_CONFIG_MACRO_DIR([m4])

CXX11_FLAGS="-fomit-frame-pointer -std=c++11 -maes -msse4.2"
PICKY_CXXFLAGS="-pedantic -Wall -Wextra -Werror"
AC_SUBST([CXX11_FLAGS])
AC_SUBST([PICKY_CXXFLAGS])

# check for c++
AC_PROG_CXX

AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([libssl], [libcrypto libssl])

AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen() function])
])

AC_CHECK_LIB(gmp, __gmpz_init, ,
  [AC_MSG_ERROR([GNU MP not found, see https://gmplib.org/])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T


AC_OUTPUT
