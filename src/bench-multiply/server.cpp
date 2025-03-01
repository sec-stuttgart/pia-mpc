#include "../secure-aggregation/common.hpp"

static_assert(input_parties.size == 5);
static_assert(input_parties.get(hmpc::constants::zero) == hmpc::constants::zero);
static_assert(input_parties.get(hmpc::constants::one) == hmpc::constants::one);
static_assert(input_parties.get(hmpc::constants::two) == hmpc::constants::two);
static_assert(input_parties.get(hmpc::constants::three) == hmpc::constants::three);
static_assert(input_parties.get(hmpc::constants::four) == hmpc::constants::four);
static_assert(compute_parties.contains(id));

constexpr auto generate_tag(auto sender, auto receiver, auto const& shape) noexcept
{
    auto mac_key = generate_mac_key();
    auto share = generate_share(sender, receiver, shape);
    auto randomness = generate_mac_randomness(get_prf_keys(), sender, receiver, shape);
    return tag(mac_key, share, randomness);
}

auto tag_ciphertext(auto prf_key, auto prg_key, auto mac_share, auto sender, auto receiver, auto k, auto c, auto const& shape)
{
    auto rand0 = hmpc::constants::zero;
    auto rand1 = hmpc::constants::one;
    auto rand2 = hmpc::constants::two;
    auto rand_count = hmpc::constants::three;

    auto u = expr::random::number_generator(
        prg_key,
        hmpc::index{rand0, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );
    auto v = expr::random::number_generator(prg_key,
        hmpc::index{rand1, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );
    auto w = expr::random::number_generator(
        prg_key,
        hmpc::index{rand2, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );
    auto s = generate_mac_randomness_share(prf_key, sender, receiver, shape);

    return c * mac_share + expr::bgv::enc(
        k,
        s,
        expr::bgv::drowning_randomness<ntt_Rq>(
            shape,
            bound,
            hmpc::constants::half, // variance u
            hmpc::constants::ten, // variance w
            u,
            v,
            w,
            statistical_security
        )
    );
}

auto tag_triple_ciphertexts(auto prf_key, auto prg_key, auto mac_share, auto sender, auto k, auto& ciphertexts, auto const& shape)
{
    return for_packed_range<hmpc::size{3}>([&](auto... i)
    {
        return std::make_tuple(
            tag_ciphertext(
                prf_key,
                prg_key,
                mac_share,
                sender,
                i,
                k,
                expr::bgv::ciphertext(std::get<i>(ciphertexts)),
                shape
            )...
        );
    });
}


int main(int argc, char** argv)
{
    auto [shape, processors] = parse_args(argc, argv);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    fmt::print("[Party {}, server, {} servers, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size(), run.info());

    auto key = run(get_public_key(id));
    std::array<cipher_type, party_count> ciphers;
    std::array<prf_key_type, party_count> prf_keys_storage;
    std::array<prg_key_type, party_count> prg_keys_storage;
    for_range<party_count>([&](auto i)
    {
        std::get<i>(ciphers) = {i.value};
        std::get<i>(prf_keys_storage) = ints::num::bit_copy<prf_key_type>(get_prf_key(i));
        std::get<i>(prg_keys_storage) = ints::num::bit_copy<prg_key_type>(get_prg_key(i));
    });
    auto mac_shares = for_packed_range<party_count>([&](auto... i)
    {
        return run(hmpc::as_tuple, generate_mac_share(compute_parties.get(i))...);
    });
    auto prf_keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            std::get<i>(prf_keys_storage).span(hmpc::access::read)...
        );
    });
    auto prg_keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            std::get<i>(prg_keys_storage).span(hmpc::access::read)...
        );
    });
    auto symmetric_keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            std::get<i>(ciphers).span(hmpc::access::read).subspan(hmpc::constants::zero, hmpc::size_constant_of<rng::key_size>)...
        );
    });
    auto nonces = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            std::get<i>(ciphers).span(hmpc::access::read).subspan(hmpc::size_constant_of<rng::key_size>)...
        );
    });
    auto symmetric_key = std::get<id>(symmetric_keys);
    auto nonce = std::get<id>(nonces);

    auto mac_key = for_packed_range<party_count>([&](auto... i)
    {
        return run(expr::mpc::shares(expr::mpc::share(std::get<i>(mac_shares))...).reconstruct());
    });

    auto [a_share, b_share, c_share, x_share, y_share, a_share_tag, b_share_tag, c_share_tag, x_share_tag, y_share_tag] = run(
        generate_share(id, hmpc::constants::zero, shape),
        generate_share(id, hmpc::constants::one, shape),
        generate_share(id, hmpc::constants::two, shape),
        generate_share(id, hmpc::constants::three, shape),
        generate_share(id, hmpc::constants::four, shape),
        generate_tag(id, hmpc::constants::zero, shape),
        generate_tag(id, hmpc::constants::one, shape),
        generate_tag(id, hmpc::constants::two, shape),
        generate_tag(id, hmpc::constants::three, shape),
        generate_tag(id, hmpc::constants::four, shape)
    );

    auto a = expr::mpc::share(a_share);
    auto b = expr::mpc::share(b_share);
    auto c = expr::mpc::share(c_share);
    auto x = expr::mpc::share(x_share);
    auto y = expr::mpc::share(y_share);

    auto a_tag = expr::tensor(a_share_tag);
    auto b_tag = expr::tensor(b_share_tag);
    auto c_tag = expr::tensor(c_share_tag);
    auto x_tag = expr::tensor(x_share_tag);
    auto y_tag = expr::tensor(y_share_tag);

    auto encrypted_triple_shares = run(
        encrypt(id, hmpc::constants::zero, a.value),
        encrypt(id, hmpc::constants::one, b.value),
        encrypt(id, hmpc::constants::two, c.value)
    );
    auto encrypted_triple_share_tag_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto ciphertexts = tag_triple_ciphertexts(
                        get_prf_key(i),
                        get_prg_key(i),
                        expr::cast<mod_q>(generate_mac_share(compute_parties.get(i)).value),
                        id,
                        expr::bgv::key(key),
                        encrypted_triple_shares,
                        shape
                    );
                    return for_packed_range<hmpc::size{3}>([&](auto... j)
                    {
                        return run(std::get<j>(ciphertexts)...);
                    });
                }
                else
                {
                    return hmpc::empty;
                }
            }()...
        );
    });

    auto signal = comp::make_tensor<hmpc::bit>(hmpc::shape{});
    {
        comp::host_accessor ok(signal, hmpc::access::discard_write);
        ok[0] = hmpc::constants::bit::one;
    }
    fmt::print("[Party {}, waiting for all {} compute parties to get ready]\n", id.value, compute_parties.size);
    run.wait();
    net.all_gather(compute_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    auto [u_shares, v_shares, encrypted_u_tags, encrypted_v_tags] = net.all_gather(
        compute_parties,
        run(x - a),
        run(y - b),
        run(
            expr::crypto::enc(
                expr::crypto::cipher(symmetric_key, nonce),
                x_tag - a_tag
            )
        ),
        run(
            expr::crypto::enc(
                expr::crypto::cipher(symmetric_key, nonce),
                y_tag - b_tag
            )
        )
    );
    time(start, "<-> shares");

    auto u = expr::mpc::shares(u_shares).reconstruct();
    auto v = expr::mpc::shares(v_shares).reconstruct();

    auto z = run(c + u * a + v * b + u * v);
    auto z_tag = run(c_tag + u * a_tag + b_tag * v);
    time(start, run, "compute xy");

    auto check_offline = for_packed_range<party_count>([&](auto... i)
    {
        return run(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto ciphertexts = tag_triple_ciphertexts(
                        std::get<i>(prf_keys),
                        std::get<i>(prg_keys),
                        expr::cast<mod_q>(expr::mpc::share(std::get<i>(mac_shares)).value),
                        id,
                        expr::bgv::key(key),
                        encrypted_triple_shares,
                        shape
                    );

                    return equal_ciphertexts(
                        as_expr(std::get<i>(encrypted_triple_share_tag_shares)),
                        ciphertexts
                    );
                }
                else
                {
                    return expr::tensor(signal); // own things are ok
                }
            }()...
        );
    });
    time(start, run, "verify off");

    auto check_online = for_packed_range<party_count>([&](auto... i)
    {
        return run(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto a_randomness = generate_mac_randomness(prf_keys, i, hmpc::constants::zero, shape);
                    auto b_randomness = generate_mac_randomness(prf_keys, i, hmpc::constants::one, shape);
                    auto x_randomness = generate_mac_randomness(prf_keys, i, hmpc::constants::three, shape);
                    auto y_randomness = generate_mac_randomness(prf_keys, i, hmpc::constants::four, shape);
                    auto u_randomness = x_randomness - a_randomness;
                    auto v_randomness = y_randomness - b_randomness;

                    auto symmetric_key = std::get<i>(symmetric_keys);
                    auto nonce = std::get<i>(nonces);

                    auto actual_u = expr::crypto::dec<plaintext>(
                        expr::crypto::cipher(symmetric_key, nonce),
                        expr::tensor(std::get<i>(encrypted_u_tags))
                    );

                    auto expected_u = tag(
                        expr::tensor(mac_key),
                        expr::mpc::shares(u_shares).get(i),
                        u_randomness
                    );

                    auto actual_v = expr::crypto::dec<plaintext>(
                        expr::crypto::cipher(symmetric_key, nonce),
                        expr::tensor(std::get<i>(encrypted_v_tags))
                    );

                    auto expected_v = tag(
                        expr::tensor(mac_key),
                        expr::mpc::shares(v_shares).get(i),
                        v_randomness
                    );

                    return expr::all(
                        (actual_u == expected_u) bitand (actual_v == expected_v)
                    );
                }
                else
                {
                    return expr::tensor(signal); // own things are ok
                }
            }()...
        );
    });
    time(start, run, "verify onl");

    for_range<party_count>([&](auto i)
    {
        comp::host_accessor ok(std::get<i>(check_offline), hmpc::access::read);
        fmt::print("[Party {}, checked party {}'s offline phase: {}]\n", id.value, i.value, ok[0]);
    });
    for_range<party_count>([&](auto i)
    {
        comp::host_accessor ok(std::get<i>(check_online), hmpc::access::read);
        fmt::print("[Party {}, checked party {}'s output: {}]\n", id.value, i.value, ok[0]);
    });
    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
