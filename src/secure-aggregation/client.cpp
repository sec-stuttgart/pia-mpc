#include "common.hpp"

static_assert(input_parties.contains(id));

int main(int argc, char** argv)
{
    auto [shape, processors] = parse_args(argc, argv);
    auto element_shape = hmpc::element_shape<plaintext>(shape);
    auto encrypted_shape = hmpc::unsqueeze(element_shape, hmpc::constants::minus_one, hmpc::size_constant_of<hmpc::traits::limb_size_v<plaintext>>);

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

    auto [mask_shares, encrypted_mask_share_tags] = net.gather<plaintext, rng::value_type>(compute_parties, hmpc::net::communicator{id, id}, shape, encrypted_shape);
    time(start, "<-  shares");

    auto mask = reconstruct(as_expr(mask_shares));
    auto masked = run(expr::tensor(input) - mask);
    time(start, run, "mask input");

    net.broadcast(compute_parties, id, masked);
    time(start, " -> masked");

    auto [output_shares, encrypted_output_share_tags] = net.all_gather<plaintext, rng::value_type>(compute_parties, all_parties, shape, encrypted_shape);
    time(start, "<-  output");

    auto [mac_shares, prf_keys_storage, prg_keys_storage] = net.all_gather<mod_p, prf_key_type, prg_key_type>(compute_parties, all_parties, hmpc::shape{}, hmpc::shapeless, hmpc::shapeless);
    time(start, run, "<-   keys ");
    auto mac_key = run(reconstruct(as_expr(mac_shares)));
    auto prf_keys = for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            std::get<i>(prf_keys_storage).span(hmpc::access::read)...
        );
    });

    auto input_ciphers = net.gather<cipher_type>(compute_parties, id, hmpc::shapeless);
    time(start, run, "<-  cipher");

    auto check = for_packed_range<party_count>([&](auto... i)
    {
        return run(
            hmpc::as_tuple,
            [&]()
            {
                auto randomness = generate_mac_randomness(prf_keys, i, input_parties.index_of(id), shape);

                auto symmetric_key = std::get<i>(input_ciphers).span(hmpc::access::read).subspan(hmpc::constants::zero, hmpc::size_constant_of<rng::key_size>);
                auto nonce = std::get<i>(input_ciphers).span(hmpc::access::read).subspan(hmpc::size_constant_of<rng::key_size>);

                auto actual = expr::crypto::dec<plaintext>(
                        expr::crypto::cipher(symmetric_key, nonce),
                        expr::tensor(std::get<i>(encrypted_mask_share_tags))
                    );
                auto expected = tag(expr::tensor(mac_key), expr::tensor(std::get<i>(mask_shares)), randomness);

                return expr::all(
                    actual == expected
                );
            }()...
        );
    });
    time(start, run, "verify onl");

    for_range<party_count>([&](auto i)
    {
        comp::host_accessor ok(std::get<i>(check), hmpc::access::read);
        fmt::print("[Party {}, checked party {}'s input: {}]\n", id.value, i.value, ok[0]);
    });
    fmt::print("[Party {}, {:nhU}]\n", id.value, net.stats());
}
