#include "common.hpp"

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

auto tag_input_ciphertexts(auto prf_key, auto prg_key, auto mac_share, auto sender, auto k, auto& ciphertexts, auto const& shape)
{
    return for_packed_range<input_party_count>([&](auto... i)
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

    try
    {
        fmt::print("[Party {}, server, {} servers, {} clients, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size(), run.info());
    }
    catch (...)
    {
        fmt::print("[Party {}, server, {} servers, {} clients, {} * {} = {} elements, failed to get device info]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size());
    }

    auto key = run(get_public_key(id));
    cipher_type cipher;
    hmpc::detail::fill_random(cipher);
    auto symmetric_key = cipher.span(hmpc::access::read).subspan(hmpc::constants::zero, hmpc::size_constant_of<rng::key_size>);
    auto nonce = cipher.span(hmpc::access::read).subspan(hmpc::size_constant_of<rng::key_size>);
    std::array<cipher_type, input_party_count> input_ciphers;
    for_range<input_party_count>([&](auto i)
    {
        hmpc::detail::fill_random(std::get<i>(input_ciphers));
    });

    auto mac_share = run(generate_mac_share(id));

    auto prf_key = ints::num::bit_copy<prf_key_type>(get_prf_key(id));
    auto prg_key = ints::num::bit_copy<prg_key_type>(get_prg_key(id));

    auto mask_shares = for_packed_range<input_party_count>([&](auto... i)
    {
        return run(hmpc::as_tuple, generate_share(id, i, shape)...);
    });
    auto mask_share_tags = for_packed_range<input_party_count>([&](auto... i)
    {
        return run(hmpc::as_tuple, generate_tag(id, i, shape)...);
    });
    auto encrypted_mask_share_tags = for_packed_range<input_party_count>([&](auto... i)
    {
        return run(
            hmpc::as_tuple,
            expr::crypto::enc(
                expr::crypto::cipher(
                    std::get<i>(input_ciphers).span(hmpc::access::read).subspan(hmpc::constants::zero, hmpc::size_constant_of<rng::key_size>),
                    std::get<i>(input_ciphers).span(hmpc::access::read).subspan(hmpc::size_constant_of<rng::key_size>)
                ),
                expr::tensor(std::get<i>(mask_share_tags))
            )...
        );
    });

    auto encrypted_mask_shares = for_packed_range<input_party_count>([&](auto... i)
    {
        return run(
            encrypt(id, i, expr::mpc::share(std::get<i>(mask_shares)).value)...
        );
    });
    auto encrypted_mask_share_tag_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto ciphertexts = tag_input_ciphertexts(
                        get_prf_key(i),
                        get_prg_key(i),
                        expr::cast<mod_q>(generate_mac_share(compute_parties.get(i)).value),
                        id,
                        expr::bgv::key(key),
                        encrypted_mask_shares,
                        shape
                    );
                    return for_packed_range<input_party_count>([&](auto... j)
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
    fmt::print("[Party {}, waiting for all {} parties to get ready]\n", id.value, all_parties.size);
    run.wait();
    net.all_gather(all_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    for_packed_range<input_party_count>([&](auto... i)
    {
        net.gather(compute_parties, input_parties.append(input_parties), std::get<i>(mask_shares)..., std::get<i>(encrypted_mask_share_tags)...);
    });
    time(start, " -> shares");

    auto masked = for_packed_range<input_party_count>([&](auto... i)
    {
        return net.broadcast<second_type<decltype(i), plaintext>...>(compute_parties, input_parties, second(i, shape)...);
    });
    time(start, "<-  masked");

    auto input_shares = for_packed_range<input_party_count>([&](auto... i)
    {
        return std::make_tuple(
            expr::mpc::share(std::get<i>(mask_shares)) + expr::tensor(std::get<i>(masked))...
        );
    });
    auto input_share_tags = as_expr(mask_share_tags);

    auto output_share = run(sum(input_shares));
    auto output_share_tag = sum(input_share_tags);
    auto encrypted_output_share_tag = run(
        expr::crypto::enc(
            expr::crypto::cipher(symmetric_key, nonce),
            output_share_tag
        )
    );
    time(start, run, "compute fn");

    auto [output_shares, encrypted_output_share_tags] = net.all_gather(compute_parties, all_parties, std::move(output_share), std::move(encrypted_output_share_tag));
    time(start, "<-> output");

    auto [mac_shares, prf_keys_storage, prg_keys_storage] = net.all_gather(compute_parties, all_parties, std::move(mac_share), std::move(prf_key), std::move(prg_key));
    time(start, run, "<->  keys ");
    auto mac_key = run(expr::mpc::shares(mac_shares).reconstruct());
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

    auto check_offline = for_packed_range<party_count>([&](auto... i)
    {
        return run(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto ciphertexts = tag_input_ciphertexts(
                        std::get<i>(prf_keys),
                        std::get<i>(prg_keys),
                        expr::cast<mod_q>(expr::mpc::shares(mac_shares).get(i).value),
                        id,
                        expr::bgv::key(key),
                        encrypted_mask_shares,
                        shape
                    );

                    return equal_ciphertexts(
                        as_expr(std::get<i>(encrypted_mask_share_tag_shares)),
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

    for_packed_range<input_party_count>([&](auto... i)
    {
        net.gather(compute_parties, input_parties, std::get<i>(input_ciphers)...);
    });
    auto ciphers = net.all_gather(compute_parties, std::move(cipher)); // Should send to input parties as well but in the demo, the input parties do not check output tags if the server do not complain
    time(start, run, "<-> cipher");

    auto check_online = for_packed_range<party_count>([&](auto... i)
    {
        return run(
            [&]()
            {
                if constexpr (i != id)
                {
                    auto input_randomness = generate_input_mac_randomness(prf_keys, i, shape);
                    auto output_randomness = [&]()
                    {
                        if constexpr (i == 0)
                        {
                            return sum(input_randomness) - expr::tensor(mac_key) * sum(as_expr(masked));
                        }
                        else
                        {
                            return sum(input_randomness);
                        }
                    }();

                    auto symmetric_key = std::get<i>(ciphers).span(hmpc::access::read).subspan(hmpc::constants::zero, hmpc::size_constant_of<rng::key_size>);
                    auto nonce = std::get<i>(ciphers).span(hmpc::access::read).subspan(hmpc::size_constant_of<rng::key_size>);

                    auto actual = expr::crypto::dec<plaintext>(
                        expr::crypto::cipher(symmetric_key, nonce),
                        expr::tensor(std::get<i>(encrypted_output_share_tags))
                    );

                    auto expected = tag(
                        expr::tensor(mac_key),
                        expr::mpc::shares(output_shares).get(i),
                        output_randomness
                    );

                    return expr::all(
                        actual == expected
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
