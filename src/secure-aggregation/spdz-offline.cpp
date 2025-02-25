#include "spdz-common.hpp"

static_assert(compute_parties.contains(id));

auto mac_check(auto& net, auto& run, auto y, auto tag_share, auto mac_key_share)
{
    auto sigma = tag_share - y * mac_key_share;
    auto sigmas = net.all_gather(compute_parties, run(sigma));
    return run(reconstruct(as_expr(sigmas)) == expr::constant_of<mod_p{}>);
}

auto check(auto& net, auto& run, auto shares, auto tag_shares, auto mac_key_share, auto const& shape)
{
    // TODO: This should be based on a broadcasted commitment
    auto r = expr::random::uniform<plaintext>(
        expr::random::number_generator(
            get_prg_key(hmpc::constants::zero),
            hmpc::index{},
            hmpc::shape{}
        ),
        shape,
        statistical_security
    );

    auto y_share = expr::sum(r * shares);
    auto y_tag_share = expr::sum(r * tag_shares);

    auto y_shares = net.all_gather(compute_parties, run(y_share));
    auto y = reconstruct(as_expr(y_shares));

    return mac_check(
        net,
        run,
        y,
        y_tag_share,
        mac_key_share
    );
}

auto encrypt_mac_share(auto party, auto mac_share)
{
    return encrypt(
        party,
        hmpc::constants::zero,
        mac_share
    );
}

template<auto Tag = []{}>
auto prepare_authentication(auto& net, auto& run, auto& signal, auto private_key, auto keys, auto mac_share, auto homomorphic_mac_share, auto share, auto encrypted_share_c0, auto encrypted_share_c1, auto const& shape)
{
    return for_packed_range<party_count>([&](auto... i)
    {
        auto coefficient_masks = run(
            hmpc::as_tuple,
            [&]()
            {
                if constexpr (i != id)
                {
                    return expr::random::uniform<Rp, unique_tag(Tag, i)>(shape, statistical_security);
                }
                else
                {
                    return expr::tensor(signal);
                }
            }()...
        );

        auto dummy = comp::bgv::ciphertext(
            comp::make_tensor<ntt_Rq>(shape),
            comp::make_tensor<ntt_Rq>(shape)
        );

        auto ciphertexts = run(
            hmpc::as_tuple,
            [&]()
            {
                if constexpr (i != id)
                {
                    auto mask = expr::bgv::enc(
                        std::get<i>(keys),
                        expr::tensor<unique_tag(Tag, i, hmpc::constants::zero)>(std::get<i>(coefficient_masks)),
                        expr::bgv::drowning_randomness<ntt_Rq>(
                            shape,
                            bound,
                            hmpc::constants::half, // variance u
                            hmpc::constants::ten, // variance w
                            {}, // randomness for u
                            {}, // randomness for v
                            {}, // randomness for w
                            statistical_security
                        )
                    );
                    return expr::bgv::ciphertext_expression{std::get<i>(encrypted_share_c0), std::get<i>(encrypted_share_c1)} * homomorphic_mac_share - mask;
                }
                else
                {
                    return expr::bgv::ciphertext(dummy);
                }
            }()...
        );

        auto my_c0 = std::make_tuple(
            std::get<i>(ciphertexts).c0...
        );
        auto my_c1 = std::make_tuple(
            std::get<i>(ciphertexts).c1...
        );

        auto [c0, c1] = net.all_to_all(compute_parties, std::move(my_c0), std::move(my_c1));

        auto tag_share = run(
            ([&]()
            {
                if constexpr (i != id)
                {
                    return expr::number_theoretic_transform(
                        expr::tensor<unique_tag(Tag, i)>(std::get<i>(coefficient_masks))
                    ) + expr::bgv::dec<plaintext>(
                        private_key,
                        expr::bgv::ciphertext<unique_tag(Tag, i)>(std::get<i>(c0), std::get<i>(c1))
                    );
                }
                else
                {
                    return share * mac_share;
                }
            }() + ...)
        );

        return tag_share;
    });
}

template<auto Tag = []{}>
auto prepare_triple(auto& net, auto& run, auto& signal, auto private_key, auto keys, auto left_share, auto left_homomorphic_share, auto const& shape)
{
    return for_packed_range<party_count>([&](auto... i)
    {
        auto right_share = run(expr::random::uniform<plaintext>(shape, statistical_security));

        auto [c, a, z, t] = zk(run, std::get<id>(keys), expr::tensor(right_share));

        auto [c0s, c1s, a0s, a1s, zs, tus, tvs, tws] = net.all_gather(compute_parties, std::move(c.c0), std::move(c.c1), std::move(a.c0), std::move(a.c1), std::move(z), std::move(t.u), std::move(t.v), std::move(t.w));

        auto checks = for_packed_range<party_count>([&](auto... i)
        {
            return std::make_tuple(
                [&]()
                {
                    if constexpr (i != id)
                    {
                        return verify_zk(
                            run,
                            std::get<i>(keys),
                            expr::bgv::ciphertext(std::get<i>(c0s), std::get<i>(c1s)),
                            expr::bgv::ciphertext(std::get<i>(a0s), std::get<i>(a1s)),
                            expr::tensor(std::get<i>(zs)),
                            expr::bgv::randomness(std::get<i>(tus), std::get<i>(tvs), std::get<i>(tws))
                        );
                    }
                    else
                    {
                        return signal;
                    }
                }()...
            );
        });

        auto coefficient_masks = run(
            hmpc::as_tuple,
            [&]()
            {
                if constexpr (i != id)
                {
                    return expr::random::uniform<Rp, unique_tag(Tag, i)>(shape, statistical_security);
                }
                else
                {
                    return expr::tensor(signal);
                }
            }()...
        );

        auto dummy = comp::bgv::ciphertext(
            comp::make_tensor<ntt_Rq>(shape),
            comp::make_tensor<ntt_Rq>(shape)
        );

        auto ciphertexts = run(
            hmpc::as_tuple,
            [&]()
            {
                if constexpr (i != id)
                {
                    auto mask = expr::bgv::enc(
                        std::get<i>(keys),
                        expr::tensor<unique_tag(Tag, i, hmpc::constants::zero)>(std::get<i>(coefficient_masks)),
                        expr::bgv::drowning_randomness<ntt_Rq>(
                            shape,
                            bound,
                            hmpc::constants::half, // variance u
                            hmpc::constants::ten, // variance w
                            {}, // randomness for u
                            {}, // randomness for v
                            {}, // randomness for w
                            statistical_security
                        )
                    );
                    return left_homomorphic_share * expr::bgv::ciphertext<unique_tag(i, hmpc::constants::two)>(std::get<i>(c0s), std::get<i>(c1s)) - mask;;
                }
                else
                {
                    return expr::bgv::ciphertext(dummy);
                }
            }()...
        );

        auto my_c0 = std::make_tuple(
            std::get<i>(ciphertexts).c0...
        );
        auto my_c1 = std::make_tuple(
            std::get<i>(ciphertexts).c1...
        );

        auto [c0, c1] = net.all_to_all(compute_parties, std::move(my_c0), std::move(my_c1));

        auto multiplied_share = run(
            ([&]()
            {
                if constexpr (i != id)
                {
                    return expr::number_theoretic_transform(
                        expr::tensor<unique_tag(Tag, i)>(std::get<i>(coefficient_masks))
                    ) + expr::bgv::dec<plaintext>(
                        private_key,
                        expr::bgv::ciphertext<unique_tag(Tag, i)>(std::get<i>(c0), std::get<i>(c1))
                    );
                }
                else
                {
                    return left_share * expr::tensor<unique_tag(hmpc::constants::one)>(right_share);
                }
            }() + ...)
        );

        return std::make_tuple(right_share, c0s, c1s, multiplied_share, checks);
    });
}


int main(int argc, char** argv)
{
    auto [input_shape, processors] = parse_args(argc, argv);
    auto shape = hmpc::unsqueeze(input_shape, hmpc::constants::minus_one, U);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    fmt::print("[Party {}, server, {} servers, {} * {} - 1 = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size() - 1, run.info());

    auto mac_share = run(generate_mac_share(id));

    auto keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            run(get_public_key(i))...
        );
    });
    auto private_key = run(get_private_key(id));

    auto homomorphic_mac_share = run(expr::cast<mod_q>(expr::tensor(mac_share)));

    auto signal = comp::make_tensor<hmpc::bit>(hmpc::shape{});
    {
        comp::host_accessor ok(signal, hmpc::access::discard_write);
        ok[0] = hmpc::constants::bit::one;
    }
    fmt::print("[Party {}, waiting for all {} compute parties to get ready]\n", id.value, compute_parties.size);
    run.wait();
    net.all_gather(compute_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    auto coeff_r = expr::random::uniform<Rp>(shape, statistical_security);
    auto [r, homomorphic_r] = run(
        expr::number_theoretic_transform(
            coeff_r
        ),
        expr::number_theoretic_transform(
            expr::cast<Rq>(
                coeff_r
            )
        )
    );

    auto [y, y_c0, y_c1, w, check_0] = prepare_triple(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::tensor(r), expr::tensor(homomorphic_r), shape);
    time(start, run, " triple w ");

    auto [v, v_c0, v_c1, u, check_1] = prepare_triple(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::tensor(r), expr::tensor(homomorphic_r), shape);
    time(start, run, " triple u ");

    auto tag_shares = prepare_authentication(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::tensor(mac_share), expr::tensor(homomorphic_mac_share), expr::tensor(y), as_expr(y_c0), as_expr(y_c1), shape);
    time(start, run, "  auth  y ");

    auto check_mac = ::check(net, run, expr::tensor(y), expr::tensor(tag_shares), expr::tensor(mac_share), shape);
    time(start, run, " mac check");

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
