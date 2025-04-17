#include "spdz-common.hpp"

static_assert(compute_parties.contains(id));

auto output_delivery(auto& net, auto& y, auto& r, auto& w, auto& v, auto& u)
{
    for_packed_range<input_party_count>([&](auto... i)
    {
        net.gather(
            compute_parties,
            input_parties.append(input_parties).append(input_parties).append(input_parties).append(input_parties),
            std::get<i>(y)...,
            std::get<i>(r)...,
            std::get<i>(w)...,
            std::get<i>(v)...,
            std::get<i>(u)...
        );
    });
}

auto authenticated_share(auto sender, auto receiver, auto const& shape)
{
    auto shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_share(compute_parties.get(i), receiver, shape)...
        );
    });

    auto value = shares.reconstruct();
    auto mac_key = generate_mac_key();

    auto mask_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_extra_share(compute_parties.get(i), receiver, shape, hmpc::constants::zero)...
        );
    });
    auto mask = mask_shares.reconstruct();

    auto i = compute_parties.index_of(sender);

    return mask_shares.get(i) + (value * mac_key - mask);
}

auto generate_input_tuple(auto sender, auto receiver, auto const& shape, auto r_id, auto v_id, auto w_id, auto u_id)
{
    auto y_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_share(compute_parties.get(i), receiver, shape)...
        );
    });

    auto r_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_extra_share(compute_parties.get(i), receiver, shape, r_id)...
        );
    });

    auto v_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_extra_share(compute_parties.get(i), receiver, shape, v_id)...
        );
    });

    auto mask_w_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_extra_share(compute_parties.get(i), receiver, shape, w_id)...
        );
    });

    auto mask_u_shares = for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_extra_share(compute_parties.get(i), receiver, shape, u_id)...
        );
    });

    auto y = y_shares.reconstruct();
    auto r = r_shares.reconstruct();
    auto v = v_shares.reconstruct();
    auto mask_w = mask_w_shares.reconstruct();
    auto mask_u = mask_u_shares.reconstruct();
    auto w = y * r;
    auto u = v * r;

    auto i = compute_parties.index_of(sender);

    return std::make_tuple(
        y_shares.get(i),
        r_shares.get(i),
        mask_w_shares.get(i) + (w - mask_w),
        v_shares.get(i),
        mask_u_shares.get(i) + (u - mask_u)
    );
}

auto mac_check(auto& net, auto& run, auto y, auto tag_share, auto mac_key_share)
{
    auto sigma = tag_share - y * mac_key_share;
    auto sigmas = net.all_gather(compute_parties, run(sigma));
    return run(expr::mpc::shares(sigmas).reconstruct() == expr::constant_of<mod_p{}>);
}

auto check(auto& net, auto& run, auto value, auto tag_share, auto mac_key_share, auto const& shape)
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

    return mac_check(
        net,
        run,
        expr::sum(r * value),
        expr::mpc::share(expr::sum(r * tag_share.value), tag_share.id, tag_share.communicator), // TODO: reduction does not work with shares yet
        mac_key_share
    );
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

    auto mac_share = run(generate_mac_share(id));

    auto [mask_shares, r, w, v, u] = for_packed_range<input_party_count>([&](auto... i)
    {
        auto shares = std::make_tuple(
            [&](){
                auto [y, r, w, v, u] = generate_input_tuple(id, i, shape, hmpc::constants::one, hmpc::constants::two, hmpc::constants::three, hmpc::constants::four);
                return run(y, r, w, v, u);
            }()...
        );

        return std::make_tuple(
            std::make_tuple(
                std::move(std::get<0>(std::get<i>(shares)))...
            ),
            std::make_tuple(
                std::move(std::get<1>(std::get<i>(shares)))...
            ),
            std::make_tuple(
                std::move(std::get<2>(std::get<i>(shares)))...
            ),
            std::make_tuple(
                std::move(std::get<3>(std::get<i>(shares)))...
            ),
            std::make_tuple(
                std::move(std::get<4>(std::get<i>(shares)))...
            )
        );
    });
    auto mask_tag_shares = for_packed_range<input_party_count>([&](auto... i)
    {
        return run(hmpc::as_tuple, authenticated_share(id, i, shape)...);
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

    output_delivery(net, mask_shares, r, w, v, u);
    time(start, " -> shares");

    auto masked = for_packed_range<input_party_count>([&](auto... i)
    {
        return net.broadcast<second_type<decltype(i), plaintext>...>(compute_parties, input_parties, second(i, shape)...);
    });
    time(start, "<-  masked");

    auto output_share = run(for_packed_range<input_party_count>([&](auto... i)
    {
        return ((expr::mpc::share(std::get<i>(mask_shares)) + expr::tensor(std::get<i>(masked))) + ...);
    }));
    auto output_tag_share = run(for_packed_range<input_party_count>([&](auto... i)
    {
        return ((expr::mpc::share(std::get<i>(mask_tag_shares)) + expr::tensor(std::get<i>(masked)) * expr::mpc::share(mac_share)) + ...);
    }));
    time(start, run, "compute fn");

    auto output_shares = net.all_gather(compute_parties, all_parties, std::move(output_share));
    time(start, "<-> output");

    auto check = ::check(net, run, expr::mpc::shares(output_shares).reconstruct(), expr::mpc::share(output_tag_share), expr::mpc::share(mac_share), shape);
    time(start, run, " mac check");
    {
        comp::host_accessor ok(check, hmpc::access::read);
        fmt::print("[Party {}, checked mac: {}]\n", id.value, ok[0]);
    }

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
