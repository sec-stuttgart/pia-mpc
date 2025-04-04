cmake_minimum_required(VERSION 3.25.0)

project(pia-mpc CXX)

find_package(hmpc 0.5.2 REQUIRED)
find_package(FMT 10 REQUIRED)


foreach(N 2 4 8 16 32)
    add_executable(mac-64-${N}
        src/mac.cpp
    )
    target_link_libraries(mac-64-${N} PRIVATE hmpc::hmpc fmt::fmt)
    target_compile_definitions(mac-64-${N} PRIVATE
        PIA_MPC_PLAINTEXT_MODULUS=0x8822d80623320001_int # 9809640459238244353
        PIA_MPC_STATISTICAL_SECURITY=64
        PIA_MPC_PARTY_COUNT=${N}
    )


    add_executable(mac-128-${N}
        src/mac.cpp
    )
    target_link_libraries(mac-128-${N} PRIVATE hmpc::hmpc fmt::fmt)
    target_compile_definitions(mac-128-${N} PRIVATE
        PIA_MPC_PLAINTEXT_MODULUS=0xd3055e85c25e7071664d1d2884720001_int # 280494985738912542904307153613171589121
        PIA_MPC_STATISTICAL_SECURITY=80
        PIA_MPC_PARTY_COUNT=${N}
    )

    list(APPEND MAC_TARGETS mac-64-${N} mac-128-${N})
endforeach()


add_executable(drowning-bgv-64
    src/drowning-bgv.cpp
)
target_link_libraries(drowning-bgv-64 PRIVATE hmpc::hmpc fmt::fmt)
target_compile_definitions(drowning-bgv-64 PRIVATE
    PIA_MPC_PLAINTEXT_MODULUS=0x8822d80623320001_int # 9809640459238244353
    PIA_MPC_LOG_N=16
    PIA_MPC_CIPHERTEXT_MODULUS=0x591f5b834c0d961f67343bcc8902bdeda2771f54306ff151162ff8d2b40f4194dc0001_int # 676310504550516370745208338938566342426856908484397554505023779011987369401721290753
    PIA_MPC_STATISTICAL_SECURITY=64
    PIA_MPC_BOUND=0x2a8af94f7f989c000000000000000000280000_int # 948737629777761053554520993225066571922669568
)


add_executable(drowning-bgv-128
    src/drowning-bgv.cpp
)
target_link_libraries(drowning-bgv-128 PRIVATE hmpc::hmpc fmt::fmt)
target_compile_definitions(drowning-bgv-128 PRIVATE
    PIA_MPC_PLAINTEXT_MODULUS=0xd3055e85c25e7071664d1d2884720001_int # 280494985738912542904307153613171589121
    PIA_MPC_LOG_N=16
    PIA_MPC_CIPHERTEXT_MODULUS=0xb271e2d502f0fe484bb79988ee13d3b615be8ca520c3dc823437584f4f670def499322c07e51826122889ac2167f0fc6c59f1a88d40001_int # 1979074704009349302955958205749626642941772258374459894984428564175802086676614232564185422620348676185507709281235287419829477441537
    PIA_MPC_STATISTICAL_SECURITY=80
    PIA_MPC_BOUND=0x41f1cf55a8e0f000000000000000000000000000000000000000280000_int # 1777862088167557546070947868375660073912324097082010113150039487938560
)


add_custom_target(verify-macs
    DEPENDS ${MAC_TARGETS}
)
add_custom_target(verify-authentication
    DEPENDS drowning-bgv-64 drowning-bgv-128
)


add_subdirectory(src/secure-aggregation secure-aggregation)


add_subdirectory(src/bench-multiply bench-multiply)
