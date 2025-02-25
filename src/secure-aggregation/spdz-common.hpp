#pragma once

#include "common.hpp"

constexpr auto extra_share_count = hmpc::constants::nine;

// for this demo, the share is deterministically derived from a prf key with value 44 and nonce `(sender, receiver)`
constexpr auto generate_extra_share(auto sender, auto receiver, auto const& shape, auto share_id) noexcept
{
    using rng = hmpc::default_random_engine;
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> key = {44};
    return expr::random::uniform<plaintext>(
        expr::random::number_generator(
            key.span(hmpc::access::read),
            hmpc::index{share_id, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
            hmpc::shape{extra_share_count, party_count_constant, input_party_count_constant}
        ),
        shape,
        statistical_security
    );
}
