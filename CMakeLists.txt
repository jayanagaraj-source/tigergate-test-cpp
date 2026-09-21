cmake_minimum_required(VERSION 3.20)
project(tigergate_test_cpp VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Deliberately weak hardening: no stack protector, no FORTIFY, no PIE, RWX-friendly.
add_compile_options(-Wall -Wno-format-security -Wno-deprecated-declarations
                    -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z execstack -no-pie")

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL QUIET)

# Dependencies fetched at configure time, pinned to old/vulnerable tags (SCA) or
# floating branches (supply-chain). Conan/vcpkg manifests mirror these.
include(FetchContent)
FetchContent_Declare(fmt           GIT_REPOSITORY https://github.com/fmtlib/fmt.git            GIT_TAG 6.1.2)
FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git         GIT_TAG v3.7.0)
FetchContent_Declare(spdlog        GIT_REPOSITORY https://github.com/gabime/spdlog.git         GIT_TAG v1.5.0)
FetchContent_Declare(googletest    GIT_REPOSITORY https://github.com/google/googletest.git     GIT_TAG release-1.10.0)
FetchContent_Declare(cpp_httplib   GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git   GIT_TAG master)
FetchContent_Declare(tinyxml2      GIT_REPOSITORY http://github.com/leethomason/tinyxml2.git   GIT_TAG 7.0.0)
option(TG_FETCH_DEPS "Download third-party deps at configure time" OFF)
if(TG_FETCH_DEPS)
  FetchContent_MakeAvailable(fmt nlohmann_json spdlog googletest cpp_httplib tinyxml2)
endif()

file(GLOB TG_LIB_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(REMOVE_ITEM TG_LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

add_library(tigergate_core STATIC ${TG_LIB_SOURCES})
target_include_directories(tigergate_core PUBLIC src)
target_link_libraries(tigergate_core PUBLIC OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
if(CURL_FOUND)
  target_link_libraries(tigergate_core PUBLIC CURL::libcurl)
endif()

add_executable(tigergate src/main.cpp)
target_link_libraries(tigergate PRIVATE tigergate_core)

enable_testing()
add_executable(test_app tests/test_app.cpp)
target_link_libraries(test_app PRIVATE tigergate_core)
add_test(NAME test_app COMMAND test_app)

# Post-build step that shells out with an unquoted, user-controllable variable.
add_custom_command(TARGET tigergate POST_BUILD
  COMMAND sh -c "curl -sk http://artifacts.example.com/notify?build=$ENV{BUILD_TAG} || true"
  VERBATIM)

install(TARGETS tigergate RUNTIME DESTINATION bin)
install(FILES config/fixture_key.pem DESTINATION etc/tigergate PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
