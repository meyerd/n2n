# - a gcrypt-config module for CMake
#
# Usage:
#   gcrypt_check(<PREFIX> [REQUIRED] <MODULE>)
#     checks if gcrypt is avialable
#
# When the 'REQUIRED' argument was set, macros will fail with an error
# when gcrypt could not be found.
#
# It sets the following variables:
#   GCRYPT_CONFIG_FOUND       ... true if libgcrypt-config works on the system
#   GCRYPT_CONFIG_EXECUTABLE  ... pathname of the libgcrypt-config program
#   <PREFIX>_FOUND            ... set to 1 if libgcrypt exist
#   <PREFIX>_LIBRARIES        ... the libraries
#   <PREFIX>_CFLAGS           ... all required cflags
#   <PREFIX>_ALGORITHMS       ... the algorithms that this libgcrypt supports
#   <PREFIX>_VERSION          ... gcrypt's version
#
# Examples:
#   gcrypt_check (GCRYPT gcrypt)
#     Check if a version of gcrypt is available, issues a warning
#     if not.
#
#   gcrypt_check (GCRYPT REQUIRED gcrypt)
#     Check if a version of gcrypt is available and fails
#     if not.
#
#   gcrypt_check (GCRYPT gcrypt>=1.4)
#     requires at least version 1.4 of gcrypt and defines e.g.
#     GCRYPT_VERSION=1.4.4. Issues a warning if a lower version
#     is available only.
#
#   gcrypt_check (GCRYPT REQUIRED gcrypt>=1.4.4)
#     requires at least version 1.4.4 of gcrypt and fails if
#     only gcrypt 1.4.3 or lower is available only.
#

# Copyright (C) 2010 Werner Dittmann <werner.dittmann@...>
#
# Redistribution and use, with or without modification, are permitted
# provided that the following conditions are met:
#
#    1. Redistributions must retain the above copyright notice, this
#       list of conditions and the following disclaimer.
#    2. The name of the author may not be used to endorse or promote
#       products derived from this software without specific prior
#       written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This is a much edited and simplified variant of the original UsePkgConfig.cmake
# from Enrico Scholz
# Copyright (C) 2006 Enrico Scholz <enrico.scholz@...>
#

### Common stuff ####
set(GCR_CONFIG_VERSION 1)
set(GCR_CONFIG_FOUND   0)

find_program(GCR_CONFIG_EXECUTABLE NAMES libgcrypt-config --version DOC "libgcrypt-config executable")
mark_as_advanced(GCR_CONFIG_EXECUTABLE)

if(GCR_CONFIG_EXECUTABLE)
  set(GCR_CONFIG_FOUND 1)
endif(GCR_CONFIG_EXECUTABLE)


# Unsets the given variables
macro(_gcrconfig_unset var)
  set(${var} "" CACHE INTERNAL "")
endmacro(_gcrconfig_unset)

macro(_gcrconfig_set var value)
  set(${var} ${value} CACHE INTERNAL "")
endmacro(_gcrconfig_set)

# Invokes libgcrypt-config, cleans up the result and sets variables
macro(_gcrconfig_invoke _gcrlist _prefix _varname _regexp)
  set(_gcrconfig_invoke_result)

  execute_process(
    COMMAND ${GCR_CONFIG_EXECUTABLE} ${ARGN}
    OUTPUT_VARIABLE _gcrconfig_invoke_result
    RESULT_VARIABLE _gcrconfig_failed)

  if (_gcrconfig_failed)
    set(_gcrconfig_${_varname} "")
    _gcrconfig_unset(${_prefix}_${_varname})
  else(_gcrconfig_failed)
    string(REGEX REPLACE "[\r\n]"                  " " _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")
    string(REGEX REPLACE " +$"                     ""  _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")

    if (NOT ${_regexp} STREQUAL "")
      string(REGEX REPLACE "${_regexp}" " " _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")
    endif(NOT ${_regexp} STREQUAL "")

    separate_arguments(_gcrconfig_invoke_result)

    #message(STATUS "  ${_varname} ... ${_gcrconfig_invoke_result}")
    set(_gcrconfig_${_varname} ${_gcrconfig_invoke_result})
    _gcrconfig_set(${_prefix}_${_varname} "${_gcrconfig_invoke_result}")
  endif(_gcrconfig_failed)
endmacro(_gcrconfig_invoke)

macro(_gcrconfig_invoke_dyn _gcrlist _prefix _varname cleanup_regexp)
  _gcrconfig_invoke("${_gcrlist}" ${_prefix}        ${_varname} "${cleanup_regexp}" ${ARGN})
endmacro(_gcrconfig_invoke_dyn)

# Splits given arguments into options and a package list
macro(_gcrconfig_parse_options _result _is_req)
  set(${_is_req} 0)
 
  foreach(_gcr ${ARGN})
    if (_gcr STREQUAL "REQUIRED")
      set(${_is_req} 1)
    endif (_gcr STREQUAL "REQUIRED")
  endforeach(_gcr ${ARGN})

  set(${_result} ${ARGN})
  list(REMOVE_ITEM ${_result} "REQUIRED")
endmacro(_gcrconfig_parse_options)

###
macro(_gcr_check_modules_internal _is_required _is_silent _prefix)
  _gcrconfig_unset(${_prefix}_FOUND)
  _gcrconfig_unset(${_prefix}_VERSION)
  _gcrconfig_unset(${_prefix}_PREFIX)
  _gcrconfig_unset(${_prefix}_LIBDIR)
  _gcrconfig_unset(${_prefix}_LIBRARIES)
  _gcrconfig_unset(${_prefix}_CFLAGS)
  _gcrconfig_unset(${_prefix}_ALGORITHMS)

  # create a better addressable variable of the modules and calculate its size
  set(_gcr_check_modules_list ${ARGN})
  list(LENGTH _gcr_check_modules_list _gcr_check_modules_cnt)

  if(GCR_CONFIG_EXECUTABLE)
    # give out status message telling checked module
    if (NOT ${_is_silent})
        message(STATUS "checking for module '${_gcr_check_modules_list}'")
    endif(NOT ${_is_silent})
   
    # iterate through module list and check whether they exist and match the required version
    foreach (_gcr_check_modules_gcr ${_gcr_check_modules_list})

      # check whether version is given
      if (_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\1" _gcr_check_modules_gcr_name "${_gcr_check_modules_gcr}")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\2" _gcr_check_modules_gcr_op   "${_gcr_check_modules_gcr}")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\3" _gcr_check_modules_gcr_ver  "${_gcr_check_modules_gcr}")
      else(_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")
        set(_gcr_check_modules_gcr_name "${_gcr_check_modules_gcr}")
        set(_gcr_check_modules_gcr_op)
        set(_gcr_check_modules_gcr_ver)
      endif(_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")

      set(_gcr_check_prefix "${_prefix}")
       
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" VERSION    ""   --version )
#      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" PREFIX     ""   --prefix )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" LIBRARIES  ""   --libs )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" CFLAGS     ""   --cflags )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" ALGORITHMS ""   --algorithms )

      message(STATUS "  found ${_gcr_check_modules_gcr}, version ${_gcrconfig_VERSION}")
      # handle the operands
      set(_gcr_wrong_version 0)
      if (_gcr_check_modules_gcr_op STREQUAL ">=")
        if((_gcr_check_modules_gcr_ver VERSION_EQUAL _gcrconfig_VERSION) OR
           (_gcrconfig_VERSION VERSION_LESS _gcr_check_modules_gcr_ver ))
          message(STATUS "  gcrypt wrong version: required: ${_gcr_check_modules_gcr_op}${_gcr_check_modules_gcr_ver}, found: ${_gcrconfig_VERSION}")
          set(_gcr_wrong_version 1)
        endif()
      endif(_gcr_check_modules_gcr_op STREQUAL ">=")

      if (_gcr_check_modules_gcr_op STREQUAL "=")
        if(_gcr_check_modules_gcr_ver VERSION_EQUAL _gcrconfig_VERSION)
          message(STATUS "  gcrypt wrong version: required: ${_gcr_check_modules_gcr_op}${_gcr_check_modules_gcr_ver}, found: ${_gcrconfig_VERSION}")
          set(_gcr_wrong_version 1)
        endif()
      endif(_gcr_check_modules_gcr_op STREQUAL "=")
     
      if (_gcr_check_modules_gcr_op STREQUAL "<=")
        if((_gcr_check_modules_gcr_ver VERSION_EQUAL _gcrconfig_VERSION) OR
           (_gcrconfig_VERSION VERSION_GREATER _gcr_check_modules_gcr_ver))
          message(STATUS "  gcrypt wrong version: required: ${_gcr_check_modules_gcr_op}${_gcr_check_modules_gcr_ver}, found: ${_gcrconfig_VERSION}")
          set(_gcr_wrong_version 1)
        endif()
      endif(_gcr_check_modules_gcr_op STREQUAL "<=")
    if (${_is_required} AND _gcr_wrong_version)
      message(FATAL_ERROR "")
    endif()

    endforeach(_gcr_check_modules_gcr)
    _gcrconfig_set(${_prefix}_FOUND 1)

  else(GCR_CONFIG_EXECUTABLE)
    if (${_is_required})
      message(FATAL_ERROR "libgcrypt-config tool not found")
    endif (${_is_required})
  endif(GCR_CONFIG_EXECUTABLE)
endmacro(_gcr_check_modules_internal)

###
### User visible macro starts here
###

###
macro(gcr_check _prefix _module0)
  # check cached value
  if (NOT DEFINED __gcr_config_checked_${_prefix} OR __gcr_config_checked_${_prefix} LESS ${GCR_CONFIG_VERSION} OR NOT ${_prefix}_FOUND)
    _gcrconfig_parse_options   (_gcr_modules _gcr_is_required "${_module0}" ${ARGN})
    _gcr_check_modules_internal("${_gcr_is_required}" 0 "${_prefix}" ${_gcr_modules})

    _gcrconfig_set(__gcr_config_checked_${_prefix} ${GCR_CONFIG_VERSION})
  endif(NOT DEFINED __gcr_config_checked_${_prefix} OR __gcr_config_checked_${_prefix} LESS ${GCR_CONFIG_VERSION} OR NOT ${_prefix}_FOUND)
endmacro(gcr_check)

###

### Local Variables:
### mode: cmake
### End:
