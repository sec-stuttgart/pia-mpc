#include "spdz-common.hpp"

static_assert(input_parties.contains(id));

auto output_delivery(hmpc::net::queue<id>& net, auto& run, auto const& shape)
{
    auto [y_shares, r_shares, w_shares, v_shares, u_shares] = net.gather<plaintext_shares, plaintext_shares, plaintext_shares, plaintext_shares, plaintext_shares>(
        compute_parties,
        hmpc::net::communicator{id, id, id, id, id},
        shape, shape, shape, shape, shape
    );
    auto y = expr::mpc::shares(y_shares).reconstruct();
    auto r = expr::mpc::shares(r_shares).reconstruct();
    auto w = expr::mpc::shares(w_shares).reconstruct();
    auto v = expr::mpc::shares(v_shares).reconstruct();
    auto u = expr::mpc::shares(u_shares).reconstruct();

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

    try
    {
        fmt::print("[Party {}, client, {} servers, {} clients, {} * {} = {} elements, device info, {:fn:nhU}]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size(), run.info());
    }
    catch (...)
    {
        fmt::print("[Party {}, client, {} servers, {} clients, {} * {} = {} elements, failed to get device info]\n", id.value, compute_parties.size, input_parties.size, shape.size(), N, element_shape.size());
    }

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
