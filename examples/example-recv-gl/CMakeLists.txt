cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)

project(example-recv-gl)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
set(LINUX 1)
endif ()

if (LINUX)
	include_directories(/opt/vc/include/)
	link_directories(/opt/vc/lib/ /usr/lib/arm-linux-gnueabihf/)
	link_libraries(bcm_host GLESv2 EGL avahi-client avahi-common pthread)
	#link_libraries(GLESv2 EGL avahi-client avahi-common pthread)
endif()

if (NOT LINUX)
# opengl
find_package(OpenGL REQUIRED)
include_directories(${OPENGL_INCLUDE_DIRS})
link_libraries(${OPENGL_LIBRARIES})

# glew
find_package(GLEW REQUIRED)
include_directories(${GLEW_INCLUDE_DIRS})
link_libraries(GLEW::GLEW)

# glfw
find_package(glfw3 REQUIRED)
include_directories(${GLFW_INCLUDE_DIRS})
link_directories(${GLFW_LIBRARY_DIRS})
link_libraries(glfw)
#add_compile_definitions(GLEW_STATIC)

endif ()
if(APPLE)
	include_directories(/usr/local/opt/ffmpeg/include)
	link_directories(/usr/local/opt/ffmpeg/lib)
endif()

find_library(LIBAVFORMAT avformat)
if(NOT LIBAVFORMAT)
    message(FATAL_ERROR "libavformat library not found")
else()
    message("   libavformat found at ${LIBAVFORMAT}")
endif()
find_library(LIBAVCODEC avcodec)
if(NOT LIBAVCODEC)
    message(FATAL_ERROR "libavcodec library not found")
else()
    message("   libavcodec found at ${LIBAVCODEC}")
endif()
find_library(LIBAVUTIL avutil)
if(NOT LIBAVUTIL)
    message(FATAL_ERROR "libavutil library not found")
else()
    message("   libavutil found at ${LIBAVUTIL}")
endif()
set(LIBAV ${LIBAVFORMAT} ${LIBAVCODEC} ${LIBAVUTIL})

include_directories(
	../../include/
)
link_directories(
	../../lib/
    ../../build/lib/
)

add_executable(example-recv-gl
	ndi_recv_gl.cpp
	../common/ogl.cpp
	../common/egl.cpp
	../common/glfw.cpp
	../common/yuv.cpp
)

target_link_libraries(example-recv-gl PRIVATE
	ndi
    avahi-client
    avahi-common
    ${LIBAV}
)
