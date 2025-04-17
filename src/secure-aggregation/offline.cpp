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


int main(int argc, char** argv)
{
    auto [input_shape, processors] = parse_args(argc, argv);
    auto shape = hmpc::unsqueeze(input_shape, hmpc::constants::minus_one, U);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    try
    {
        fmt::print("[Party {}, server, {} servers, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size(), run.info());
    }
    catch (...)
    {
        fmt::print("[Party {}, server, {} servers, {} * {} = {} elements, failed to get device info]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size());
    }

    auto keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            run(get_public_key(i))...
        );
    });
    auto private_key = run(get_private_key(id));

    auto mac_share = run(generate_mac_share(id));

    auto prf_key = ints::num::bit_copy<prf_key_type>(get_prf_key(id));
    auto prg_key = ints::num::bit_copy<prg_key_type>(get_prg_key(id));

    auto dummy = comp::bgv::ciphertext(
        comp::make_tensor<ntt_Rq>(shape),
        comp::make_tensor<ntt_Rq>(shape)
    );

    auto signal = comp::make_tensor<hmpc::bit>(hmpc::shape{});
    {
        comp::host_accessor ok(signal, hmpc::access::discard_write);
        ok[0] = hmpc::constants::bit::one;
    }
    fmt::print("[Party {}, waiting for all {} compute parties to get ready]\n", id.value, compute_parties.size);
    run.wait();
    net.all_gather(compute_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    auto share = run(expr::mpc::share(expr::random::uniform<plaintext>(shape, statistical_security), id, compute_parties));

    auto [c, a, z, t] = zk(run, expr::bgv::key(std::get<id>(keys)), expr::mpc::share(share).value);
    time(start, run, "compute zk");

    auto [cs, as, zs, ts] = net.all_gather(compute_parties, std::move(c), std::move(a), std::move(z), std::move(t));
    time(start, run, "<->  zks  ");

    auto checks = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            [&]()
            {
                if constexpr (i != id)
                {
                    return verify_zk(
                        run,
                        expr::bgv::key(std::get<i>(keys)),
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
    time(start, run, "verify zks");

    auto authenticated_share = for_packed_range<party_count>([&](auto... i)
    {
        auto ciphertexts = run(
            hmpc::as_tuple,
            [&]()
            {
                if constexpr (i != id)
                {
                    return tag_ciphertext(
                        prf_key.span(hmpc::access::read),
                        prg_key.span(hmpc::access::read),
                        expr::cast<mod_q>(expr::mpc::share(mac_share).value),
                        i,
                        hmpc::constants::zero,
                        expr::bgv::key<unique_tag(i, hmpc::constants::one)>(std::get<i>(keys)),
                        expr::bgv::ciphertext<unique_tag(i, hmpc::constants::two)>(std::get<i>(cs)),
                        shape
                    );
                }
                else
                {
                    return expr::bgv::ciphertext(dummy);
                }
            }()...
        );

        auto other_ciphertexts = net.all_to_all(compute_parties, std::move(ciphertexts));
        time(start, run, "<-> c txt ");

        return run(
            ([&]()
            {
                if constexpr (i == id)
                {
                    return expr::mpc::share(share).value * expr::mpc::share(mac_share).value + generate_mac_randomness_share(prf_key.span(hmpc::access::read), id, hmpc::constants::zero, shape);
                }
                else
                {
                    return expr::bgv::dec<plaintext>(
                        expr::tensor<unique_tag(hmpc::constants::two)>(private_key),
                        expr::bgv::ciphertext<unique_tag(i, hmpc::constants::two)>(std::get<i>(other_ciphertexts))
                    );
                }
            }() + ...)
        );
    });
    time(start, run, "auth share");

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
