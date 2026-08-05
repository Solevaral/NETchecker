cmake_minimum_required(VERSION 3.20) # Ставь 3.20 для совместимости, или свою 4.3
project(network_diag LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ищем все .cpp файлы в папке src (или замени на main.cpp, если файл в корне)
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*.cpp main.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

# Линк Winsock2 только для Windows
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()
