set(COMPUTE_PARTY_COUNT 2 CACHE STRING "Number of compute parties for secure aggregation demo")
math(EXPR LAST_COMPUTE_PARTY "${COMPUTE_PARTY_COUNT}-1")
set(INPUT_PARTY_COUNT 2 CACHE STRING "Number of input parties for secure aggregation demo")
math(EXPR LAST_INPUT_PARTY "${INPUT_PARTY_COUNT}-1")

set(SECURE_AGGREGATION_SERVERS)
set(SECURE_AGGREGATION_CLIENTS)
set(SECURE_AGGREGATION_OFFLINE)
set(SECURE_AGGREGATION_SPDZ_SERVERS)
set(SECURE_AGGREGATION_SPDZ_CLIENTS)
set(SECURE_AGGREGATION_SPDZ_OFFLINE)

foreach(N RANGE ${LAST_COMPUTE_PARTY})
    list(APPEND COMPUTE_PARTIES ${N})
endforeach()
list(JOIN COMPUTE_PARTIES ", " COMPUTE_PARTIES)

foreach(N RANGE ${LAST_INPUT_PARTY})
    math(EXPR PARTY_ID "${COMPUTE_PARTY_COUNT}+${N}")
    list(APPEND INPUT_PARTIES ${PARTY_ID})
endforeach()
list(JOIN INPUT_PARTIES ", " INPUT_PARTIES)

message("PIA-MPC: Secure aggregation:\n - ${COMPUTE_PARTY_COUNT} compute parties: ${COMPUTE_PARTIES}\n - ${INPUT_PARTY_COUNT} input parties: ${INPUT_PARTIES}")

foreach(N RANGE ${LAST_INPUT_PARTY})
    add_executable(client-${N}
        client.cpp
    )
    target_link_libraries(client-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    math(EXPR PARTY_ID "${COMPUTE_PARTY_COUNT}+${N}")
    target_compile_definitions(client-${N} PRIVATE
        PIA_MPC_PARTY_ID=${PARTY_ID}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    add_executable(spdz-client-${N}
        spdz-client.cpp
    )
    target_link_libraries(spdz-client-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    math(EXPR PARTY_ID "${COMPUTE_PARTY_COUNT}+${N}")
    target_compile_definitions(spdz-client-${N} PRIVATE
        PIA_MPC_PARTY_ID=${PARTY_ID}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    list(APPEND SECURE_AGGREGATION_CLIENTS client-${N})
    list(APPEND SECURE_AGGREGATION_SPDZ_CLIENTS spdz-client-${N})
endforeach()


foreach(N RANGE ${LAST_COMPUTE_PARTY})
    add_executable(server-${N}
        server.cpp
    )
    target_link_libraries(server-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(server-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    add_executable(offline-${N}
        offline.cpp
    )
    target_link_libraries(offline-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(offline-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
    )

    add_executable(spdz-server-${N}
        spdz-server.cpp
    )
    target_link_libraries(spdz-server-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(spdz-server-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
        PIA_MPC_INPUT_PARTIES=${INPUT_PARTIES}
    )

    add_executable(spdz-offline-${N}
        spdz-offline.cpp
    )
    target_link_libraries(spdz-offline-${N} PRIVATE hmpc::hmpc hmpc::hmpc_rs fmt::fmt)
    target_compile_definitions(spdz-offline-${N} PRIVATE
        PIA_MPC_PARTY_ID=${N}
        PIA_MPC_COMPUTE_PARTIES=${COMPUTE_PARTIES}
    )

    list(APPEND SECURE_AGGREGATION_SERVERS server-${N})
    list(APPEND SECURE_AGGREGATION_OFFLINE offline-${N})
    list(APPEND SECURE_AGGREGATION_SPDZ_SERVERS spdz-server-${N})
    list(APPEND SECURE_AGGREGATION_SPDZ_OFFLINE spdz-offline-${N})
endforeach()

add_custom_target(clients
    DEPENDS ${SECURE_AGGREGATION_CLIENTS}
)
add_custom_target(servers
    DEPENDS ${SECURE_AGGREGATION_SERVERS}
)
add_custom_target(offline
    DEPENDS ${SECURE_AGGREGATION_OFFLINE}
)
add_custom_target(spdz-clients
    DEPENDS ${SECURE_AGGREGATION_SPDZ_CLIENTS}
)
add_custom_target(spdz-servers
    DEPENDS ${SECURE_AGGREGATION_SPDZ_SERVERS}
)
add_custom_target(spdz-offline
    DEPENDS ${SECURE_AGGREGATION_SPDZ_OFFLINE}
)
