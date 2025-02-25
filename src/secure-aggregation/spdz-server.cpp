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
        return std::make_tuple(
            generate_share(i, receiver, shape)...
        );
    });

    auto value = reconstruct(shares);
    auto mac_key = generate_mac_key();

    auto mask_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_extra_share(i, receiver, shape, hmpc::constants::zero)...
        );
    });
    auto mask = reconstruct(mask_shares);

    if constexpr (sender == 0)
    {
        return value * mac_key - mask + std::get<sender>(mask_shares);
    }
    else
    {
        return std::get<sender>(mask_shares);
    }
}

auto generate_input_tuple(auto sender, auto receiver, auto const& shape, auto r_id, auto v_id, auto w_id, auto u_id)
{
    auto y_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_share(i, receiver, shape)...
        );
    });

    auto r_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_extra_share(i, receiver, shape, r_id)...
        );
    });

    auto v_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_extra_share(i, receiver, shape, v_id)...
        );
    });

    auto mask_w_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_extra_share(i, receiver, shape, w_id)...
        );
    });

    auto mask_u_shares = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            generate_extra_share(i, receiver, shape, u_id)...
        );
    });

    auto y = reconstruct(y_shares);
    auto r = reconstruct(r_shares);
    auto v = reconstruct(v_shares);
    auto mask_w = reconstruct(mask_w_shares);
    auto mask_u = reconstruct(mask_u_shares);
    auto w = y * r;
    auto u = v * r;

    if constexpr (sender == 0)
    {
        return std::make_tuple(
            std::get<sender>(y_shares),
            std::get<sender>(r_shares),
            w - mask_w + std::get<sender>(mask_w_shares),
            std::get<sender>(v_shares),
            u - mask_u + std::get<sender>(mask_u_shares)
        );
    }
    else
    {
        return std::make_tuple(
            std::get<sender>(y_shares),
            std::get<sender>(r_shares),
            std::get<sender>(mask_w_shares),
            std::get<sender>(v_shares),
            std::get<sender>(mask_u_shares)
        );
    }
}

auto mac_check(auto& net, auto& run, auto y, auto tag_share, auto mac_key_share)
{
    auto sigma = tag_share - y * mac_key_share;
    auto sigmas = net.all_gather(compute_parties, run(sigma));
    return run(reconstruct(as_expr(sigmas)) == expr::constant_of<mod_p{}>);
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
        expr::sum(r * tag_share),
        mac_key_share
    );
}


int main(int argc, char** argv)
{
    auto [shape, processors] = parse_args(argc, argv);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    fmt::print("[Party {}, server, {} servers, {} clients, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size(), run.info());

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

    auto input_shares = [&]()
    {
        if constexpr (id == 0)
        {
            return add(as_expr(mask_shares), as_expr(masked));
        }
        else
        {
            return as_expr(mask_shares);
        }
    }();
    auto input_tag_shares = add(as_expr(mask_tag_shares), mul_scalar(expr::tensor(mac_share), as_expr(masked)));

    auto output_share = run(sum(input_shares));
    auto output_tag_share = run(sum(input_tag_shares));
    time(start, run, "compute fn");

    auto output_shares = net.all_gather(compute_parties, all_parties, std::move(output_share));
    time(start, "<-> output");

    auto check = ::check(net, run, reconstruct(as_expr(output_shares)), expr::tensor(output_tag_share), expr::tensor(mac_share), shape);
    time(start, run, " mac check");
    {
        comp::host_accessor ok(check, hmpc::access::read);
        fmt::print("[Party {}, checked mac: {}]\n", id.value, ok[0]);
    }

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
