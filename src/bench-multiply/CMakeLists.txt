set(COMPUTE_PARTY_COUNT 2 CACHE STRING "Number of compute parties for secure aggregation demo")
math(EXPR LAST_COMPUTE_PARTY "${COMPUTE_PARTY_COUNT}-1")

foreach(N RANGE ${LAST_COMPUTE_PARTY})
    list(APPEND COMPUTE_PARTIES ${N})
endforeach()
list(JOIN COMPUTE_PARTIES ", " COMPUTE_PARTIES)

set(INPUT_PARTIES "0, 1, 2, 3, 4")

message("PIA-MPC: Benchmark multiplication:\n - ${COMPUTE_PARTY_COUNT} compute parties: ${COMPUTE_PARTIES}")

foreach(N RANGE ${LAST_COMPUTE_PARTY})
    add_executable(server-multiply-${N}
        server.cpp
    )
    target_link_libraries(server-multiply-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(server-multiply-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    add_executable(spdz-server-multiply-${N}
        spdz-server.cpp
    )
    target_link_libraries(spdz-server-multiply-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(spdz-server-multiply-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    list(APPEND BENCH_MULTIPLY_SERVERS server-multiply-${N})
    list(APPEND BENCH_MULTIPLY_SPDZ_SERVERS spdz-server-multiply-${N})
endforeach()

add_custom_target(servers-multiply
    DEPENDS ${BENCH_MULTIPLY_SERVERS}
)
add_custom_target(spdz-servers-multiply
    DEPENDS ${BENCH_MULTIPLY_SPDZ_SERVERS}
)
add_custom_target(benchmark-multiply
    DEPENDS servers-multiply spdz-servers-multiply
)
