#!/bin/bash

# Set default Lua engine based on environment or availability
if [ -n "$LUA_DEFAULT_ENGINE" ]; then
    LUA_ENGINE="$LUA_DEFAULT_ENGINE"
elif command -v luajit >/dev/null 2>&1; then
    LUA_ENGINE="luajit"
else
    LUA_ENGINE="lua5.1"
fi
DEBUG=0

# Set variables
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../build"
LUA_DIR=${BUILD_DIR}/lua
CERTS_DIR="${LUA_DIR}/certs/client"

# Help function
show_help() {
    echo "Usage: $0 [-e engine] [-d] <lua_script>"
    echo "Options:"
        echo "  -e  Lua engine to use (lua5.1 or luajit) [default: $LUA_ENGINE]"
        echo "  -d  Enable debug output"
        echo "  -h  Show this help message"
}

# Parse command line arguments
while getopts "e:dh" opt; do
    case $opt in
        e) LUA_ENGINE="$OPTARG";;
        d) DEBUG=1;;
        h) show_help; exit 0;;
        \?) echo "Invalid option -$OPTARG"; show_help; exit 1;;
    esac
done

# Shift to get the script name
shift $((OPTIND-1))
LUA_SCRIPT="$1"

# Validate input
if [ -z "$LUA_SCRIPT" ]; then
    echo "Error: No Lua script specified"
    show_help
    exit 1
fi

# Convert relative path to absolute path from current working directory
if [[ "$LUA_SCRIPT" != /* ]]; then
    LUA_SCRIPT="$(pwd)/$LUA_SCRIPT"
fi

# Clean up path (remove ./ ../ etc)
LUA_SCRIPT=$(realpath --relative-to="$LUA_DIR" "$LUA_SCRIPT")

if [ ! -f "$LUA_SCRIPT" ] && [ ! -f "$LUA_DIR/$LUA_SCRIPT" ]; then
    echo "Error: Script file '$LUA_SCRIPT' not found"
    exit 1
fi

if [ "$LUA_ENGINE" != "lua5.1" ] && [ "$LUA_ENGINE" != "luajit" ]; then
    echo "Error: Invalid Lua engine specified. Use 'lua5.1' or 'luajit'"
    exit 1
fi

# Set up environment
cd ${LUA_DIR}
export LD_LIBRARY_PATH="../c/lib:$LD_LIBRARY_PATH"
export KC_PKCE_LIB="../c/lib/libkc_pkce.so"

# Run the Lua script
if [ $DEBUG -eq 1 ]; then
    echo "Running with $LUA_ENGINE:"
    echo "Working directory: $(pwd)"
    echo "Script: $LUA_SCRIPT"
    echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
    echo "KC_PKCE_LIB: $KC_PKCE_LIB"
fi

$LUA_ENGINE "$LUA_SCRIPT"
