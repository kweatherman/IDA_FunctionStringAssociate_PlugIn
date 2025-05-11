
// Common includes and defines
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen)

// IDA SDK
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#pragma warning(push)
#pragma warning(disable:4244) // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267) // conversion from 'size_t' to 'uint32', possible loss of data
#pragma warning(disable:4018) // warning C4018: '<': signed/unsigned mismatch
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <typeinf.hpp>
#pragma warning(pop)

#include <Utility.h>

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 10, 0, 0)
