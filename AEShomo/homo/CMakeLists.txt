# file(GLOB test_sources RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.cpp")


#add_executable(homosm4 SM4.cpp SM4_homo.cpp)
#target_link_libraries(homosm4 tfhe++ )

#####add_executable(enc enc_homo.cpp)
#####target_link_libraries(enc tfhe++ )

#####add_executable(dec dec_homo.cpp)
#####target_link_libraries(dec tfhe++ )
#####add_executable(d homo.cpp)
#####target_link_libraries(d tfhe++ )


add_executable(e enc.cpp)
target_link_libraries(e tfhe++ )

#####add_executable(dec DEC_homo.cpp)
#####target_link_libraries(dec tfhe++ )

#####add_executable(d dec.cpp)
#####target_link_libraries(d tfhe++ )

#####add_executable(dec dec_homo.cpp)
#####target_link_libraries(dec tfhe++ )
#####add_executable(AES AES_homo.cpp)
#####target_link_libraries(AES tfhe++ )
# foreach(test_source ${test_sources})
#     string( REPLACE ".cpp" "" test_name ${test_source} )
#     add_executable(${test_name} ${test_source})
#     target_link_libraries(${test_name} tfhe++ )
# endforeach(test_source ${test_sources})

# # For GMP used in INTorus test
# find_library(gmp NAMES gmp gmpxx)
# if(gmp)
#     add_compile_definitions(ENABLE_LSHTEST)
#     target_link_libraries(INTorus gmp)
# endif()

# add_subdirectory(axell)