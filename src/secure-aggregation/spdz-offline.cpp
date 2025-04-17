#include "spdz-common.hpp"

static_assert(compute_parties.contains(id));

auto mac_check(auto& net, auto& run, auto y, auto tag_share, auto mac_key_share)
{
    auto sigma = tag_share - y * mac_key_share;
    auto sigmas = net.all_gather(compute_parties, run(sigma));
    return run(expr::mpc::shares(sigmas).reconstruct() == expr::constant_of<mod_p{}>);
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

    // TODO: reduction does not work with shares yet
    auto y_share = expr::mpc::share(expr::sum(r * shares), id, compute_parties);
    auto y_tag_share = expr::mpc::share(expr::sum(r * tag_shares.value), tag_shares.id, tag_shares.communicator);

    auto y_shares = net.all_gather(compute_parties, run(y_share));
    auto y = expr::mpc::shares(y_shares).reconstruct();

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
auto prepare_authentication(auto& net, auto& run, auto& signal, auto private_key, auto keys, auto mac_share, auto homomorphic_mac_share, auto share, auto encrypted_share, auto const& shape)
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
                    return std::get<i>(encrypted_share) * homomorphic_mac_share - mask;
                }
                else
                {
                    return expr::bgv::ciphertext(dummy);
                }
            }()...
        );

        auto other_ciphertexts = net.all_to_all(compute_parties, std::move(ciphertexts));

        auto tag_share = run(
            expr::mpc::share(
                ([&]()
                {
                    if constexpr (i != id)
                    {
                        return expr::number_theoretic_transform(
                            expr::tensor<unique_tag(Tag, i)>(std::get<i>(coefficient_masks))
                        ) + expr::bgv::dec<plaintext>(
                            private_key,
                            expr::bgv::ciphertext<unique_tag(Tag, i)>(std::get<i>(other_ciphertexts))
                        );
                    }
                    else
                    {
                        return share * mac_share.value;
                    }
                }() + ...),
                id,
                compute_parties
            )
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

        auto [cs, as, zs, ts] = net.all_gather(compute_parties, std::move(c), std::move(a), std::move(z), std::move(t));

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
                            expr::bgv::ciphertext(std::get<i>(cs)),
                            expr::bgv::ciphertext(std::get<i>(as)),
                            expr::tensor(std::get<i>(zs)),
                            expr::bgv::randomness(std::get<i>(ts))
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
                    return left_homomorphic_share * expr::bgv::ciphertext<unique_tag(i, hmpc::constants::two)>(std::get<i>(cs)) - mask;;
                }
                else
                {
                    return expr::bgv::ciphertext(dummy);
                }
            }()...
        );

        auto other_ciphertexts = net.all_to_all(compute_parties, std::move(ciphertexts));

        auto multiplied_share = run(
            ([&]()
            {
                if constexpr (i != id)
                {
                    return expr::number_theoretic_transform(
                        expr::tensor<unique_tag(Tag, i)>(std::get<i>(coefficient_masks))
                    ) + expr::bgv::dec<plaintext>(
                        private_key,
                        expr::bgv::ciphertext<unique_tag(Tag, i)>(std::get<i>(other_ciphertexts))
                    );
                }
                else
                {
                    return left_share * expr::tensor<unique_tag(hmpc::constants::one)>(right_share);
                }
            }() + ...)
        );

        return std::make_tuple(right_share, other_ciphertexts, multiplied_share, checks);
    });
}


int main(int argc, char** argv)
{
    auto [input_shape, processors] = parse_args(argc, argv);
    auto shape = hmpc::unsqueeze(input_shape, hmpc::constants::minus_one, U);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    try
    {
        fmt::print("[Party {}, server, {} servers, {} * {} - 1 = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size() - 1, run.info());
    }
    catch (...)
    {
        fmt::print("[Party {}, server, {} servers, {} * {} - 1 = {} elements, failed to get device info]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size() - 1);
    }

    auto mac_share = run(generate_mac_share(id));

    auto keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            run(get_public_key(i))...
        );
    });
    auto private_key = run(get_private_key(id));

    auto homomorphic_mac_share = run(expr::cast<mod_q>(expr::mpc::share(mac_share).value));

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

    auto [y, y_ciphertexts, w, check_0] = prepare_triple(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::tensor(r), expr::tensor(homomorphic_r), shape);
    time(start, run, " triple w ");

    auto [v, v_ciphertexts, u, check_1] = prepare_triple(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::tensor(r), expr::tensor(homomorphic_r), shape);
    time(start, run, " triple u ");

    auto tag_shares = prepare_authentication(net, run, signal, expr::tensor(private_key), as_expr(keys), expr::mpc::share(mac_share), expr::tensor(homomorphic_mac_share), expr::tensor(y), as_expr(y_ciphertexts), shape);
    time(start, run, "  auth  y ");

    auto check_mac = ::check(net, run, expr::tensor(y), expr::mpc::share(tag_shares), expr::mpc::share(mac_share), shape);
    time(start, run, " mac check");

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
