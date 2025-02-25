#include "spdz-common.hpp"

static_assert(input_parties.contains(id));

auto output_delivery(hmpc::net::queue<id>& net, auto& run, auto const& shape)
{
    auto [y_shares, r_shares, w_shares, v_shares, u_shares] = net.gather<plaintext, plaintext, plaintext, plaintext, plaintext>(
        compute_parties,
        hmpc::net::communicator{id, id, id, id, id},
        shape, shape, shape, shape, shape
    );
    auto y = reconstruct(as_expr(y_shares));
    auto r = reconstruct(as_expr(r_shares));
    auto w = reconstruct(as_expr(w_shares));
    auto v = reconstruct(as_expr(v_shares));
    auto u = reconstruct(as_expr(u_shares));

    auto [output, check] = run(y, expr::all(w == y * r) bitand expr::all(u == v * r));
    {
        comp::host_accessor ok(check, hmpc::access::read);
        fmt::print("[Party {}, checked input: {}]\n", id.value, ok[0]);
    }
    return std::move(output);
}


int main(int argc, char** argv)
{
    auto [shape, processors] = parse_args(argc, argv);
    auto element_shape = hmpc::element_shape<plaintext>(shape);

    auto run = comp::queue(sycl::queue{processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v});
    auto net = comm::queue(id, comm::config::read_env(config));

    fmt::print("[Party {}, client, {} servers, {} clients, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size(), run.info());

    auto input = run(generate_input(input_parties.index_of(id), shape));

    auto signal = comp::make_tensor<hmpc::bit>(hmpc::shape{});
    {
        comp::host_accessor ok(signal, hmpc::access::discard_write);
        ok[0] = hmpc::constants::bit::one;
    }
    fmt::print("[Party {}, waiting for all {} parties to get ready]\n", id.value, all_parties.size);
    run.wait();
    net.all_gather(all_parties, auto(signal)); // copy signal instead of moving to keep it for later

    auto start = ::start();

    auto mask = output_delivery(net, run, shape);
    time(start, "<-  shares");

    auto masked = run(expr::tensor(input) - expr::tensor(mask));
    time(start, run, "mask input");

    net.broadcast(compute_parties, id, masked);
    time(start, " -> masked");

    auto output_shares = net.all_gather<plaintext>(compute_parties, all_parties, shape);
    time(start, "<-  output");

    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
