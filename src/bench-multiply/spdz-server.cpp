#include "../secure-aggregation/spdz-common.hpp"

static_assert(input_parties.size == 5);
static_assert(input_parties.get(hmpc::constants::zero) == hmpc::constants::zero);
static_assert(input_parties.get(hmpc::constants::one) == hmpc::constants::one);
static_assert(input_parties.get(hmpc::constants::two) == hmpc::constants::two);
static_assert(input_parties.get(hmpc::constants::three) == hmpc::constants::three);
static_assert(input_parties.get(hmpc::constants::four) == hmpc::constants::four);
static_assert(compute_parties.contains(id));

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

int main(int argc, char** argv)
{
    auto [shape, processors] = parse_args(argc, argv);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    fmt::print("[Party {}, server, {} servers, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, shape.size(), N, element_shape.size(), run.info());

    auto mac_share = run(generate_mac_share(id));

    auto [a_share, b_share, c_share, x_share, y_share, a_share_tag, b_share_tag, c_share_tag, x_share_tag, y_share_tag] = run(
        generate_share(id, hmpc::constants::zero, shape),
        generate_share(id, hmpc::constants::one, shape),
        generate_share(id, hmpc::constants::two, shape),
        generate_share(id, hmpc::constants::three, shape),
        generate_share(id, hmpc::constants::four, shape),
        authenticated_share(id, hmpc::constants::zero, shape),
        authenticated_share(id, hmpc::constants::one, shape),
        authenticated_share(id, hmpc::constants::two, shape),
        authenticated_share(id, hmpc::constants::three, shape),
        authenticated_share(id, hmpc::constants::four, shape)
    );

    auto a = expr::tensor(a_share);
    auto b = expr::tensor(b_share);
    auto c = expr::tensor(c_share);
    auto x = expr::tensor(x_share);
    auto y = expr::tensor(y_share);

    auto a_tag = expr::tensor(a_share_tag);
    auto b_tag = expr::tensor(b_share_tag);
    auto c_tag = expr::tensor(c_share_tag);
    auto x_tag = expr::tensor(x_share_tag);
    auto y_tag = expr::tensor(y_share_tag);

    auto signal = comp::make_tensor<hmpc::bit>(hmpc::shape{});
    {
        comp::host_accessor ok(signal, hmpc::access::discard_write);
        ok[0] = hmpc::constants::bit::one;
    }
    fmt::print("[Party {}, waiting for all {} compute parties to get ready]\n", id.value, compute_parties.size);
    run.wait();
    net.all_gather(compute_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    auto [u_tag, v_tag] = run(x_tag - a_tag, y_tag - b_tag);
    auto [u_shares, v_shares] = net.all_gather(compute_parties, run(x - a), run(y - b));
    time(start, run, "<-> shares");

    auto u = reconstruct(as_expr(u_shares));
    auto v = reconstruct(as_expr(v_shares));

    auto z = [&]()
    {
        if constexpr (id == 0)
        {
            return run(
                c + u * a + b * v + u * v
            );
        }
        else
        {
            return run(
                c + u * a + b * v
            );
        }
    }();
    auto z_tag = run(c_tag + u * a_tag + b_tag * v);
    time(start, run, "compute xy");

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
