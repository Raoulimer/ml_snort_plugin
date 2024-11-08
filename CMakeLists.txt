cmake_minimum_required ( VERSION 3.5 )
project ( ml_classifiers CXX )

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_compile_definitions(PROJECT_ROOT_DIR="${PROJECT_ROOT_DIR}")

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )
#Unfortunately neither scikit-learn nor xgboost provide pkg-config support. Neither of them seem to be aware of CMAKE either

add_library (
    ml_classifiers MODULE
    src/core/ml_classifiers.cc
    include/ml_classifiers.h
    src/featureExtraction/connection.h
    src/featureExtraction/connection.cc
)


set_target_properties (
    ml_classifiers
    PROPERTIES
        PREFIX ""
)

find_package ( Python3 REQUIRED COMPONENTS Interpreter Development )
find_package ( Boost COMPONENTS python${Python3_VERSION_MAJOR}${Python3_VERSION_MINOR} )


message ( "[*] PYTHON_LIBRARY_DIRS: ${Python3_LIBRARY_DIRS}" )
message ( "[*] PYTHON_LIBRARIES: ${Python3_LIBRARIES}" )
message ( "[*] PYTHON_EXECUTABLE: ${Python3_EXECUTABLE}" )
message ( "[*] PYTHON_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}" )

message ( "[*] BOOST_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}" )
message ( "[*] BOOST_LIBRARIES: ${Boost_LIBRARIES}" )
message ( "[*] BOOST_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}" )

message("[*] SNORT3_LIBRARY_DIRS: ${SNORT3_LIBRARY_DIRS}")
message("[*] SNORT3_LIBRARIES: ${SNORT3_LIBRARIES}")
message("[*] SNORT3_INCLUDE_DIRS: ${SNORT3_INCLUDE_DIRS}")

include_directories(${PROJECT_ROOT_DIR} ${Python3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${SNORT3_INCLUDE_DIRS})
target_link_libraries(ml_classifiers ${Python3_LIBRARIES} ${Boost_LIBRARIES} ${SNORT3_LIBRARIES})

target_include_directories (
    ml_classifiers PUBLIC
    ${PROJECT_ROOT_DIR}
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ml_classifiers
    LIBRARY
        DESTINATION "/usr/local/snort/lib/snort/plugins/alternative/${CMAKE_PROJECT_NAME}/inspectors"
)
