#include <hmpc/comp/accessor.hpp>
#include <hmpc/comp/tensor.hpp>
#include <hmpc/comp/queue.hpp>
#include <hmpc/expr/binary_expression.hpp>
#include <hmpc/expr/tensor.hpp>
#include <hmpc/expr/random/uniform.hpp>
#include <hmpc/expr/random/uniform_from_number_generator.hpp>
#include <hmpc/expr/value.hpp>
#include <hmpc/ints/mod.hpp>
#include <hmpc/ints/literals.hpp>
#include <hmpc/random/number_generator.hpp>

#include <fmt/format.h>
#include <sycl/sycl.hpp>

#include <charconv>
#include <chrono>

auto main(int argc, char** raw_argv) -> int
{
    using namespace hmpc::ints::literals;
    using namespace hmpc::expr::operators;
    constexpr auto p = PIA_MPC_PLAINTEXT_MODULUS;
    using mod_p = hmpc::ints::mod<p>;

    using rng = hmpc::default_random_engine;
    hmpc::core::limb_array<rng::key_size, rng::value_type> key_storage = {42};
    auto prf_key = key_storage.span(hmpc::access::read);
    constexpr auto party_count = hmpc::size_constant_of<PIA_MPC_PARTY_COUNT>;

    std::size_t n = 100;
    std::vector<std::string_view> argv(raw_argv, raw_argv + argc);
    if (argc > 1)
    {
        std::from_chars(argv[1].data(), argv[1].data() + argv[1].size(), n);
    }
    int processors = 1;
    if (argc > 2)
    {
        std::from_chars(argv[2].data(), argv[2].data() + argv[2].size(), processors);
    }

    sycl::queue sycl_queue(processors < 0 ? sycl::gpu_selector_v : sycl::cpu_selector_v);
    hmpc::comp::queue queue(sycl_queue);

    auto x_storage = queue(
        hmpc::expr::random::uniform<mod_p>(hmpc::shape{n})
    );

    auto alpha = hmpc::expr::value(mod_p{42_int});

    queue.wait();
    auto start = std::chrono::high_resolution_clock::now();

    auto x = hmpc::expr::tensor(x_storage);
    auto r = hmpc::iter::for_packed_range<hmpc::size{PIA_MPC_PARTY_COUNT}>([&](auto... i)
    {
        return (hmpc::expr::random::uniform<mod_p>(
            hmpc::expr::random::number_generator(prf_key, hmpc::index{i}, hmpc::shape{party_count}),
            hmpc::shape{n},
            hmpc::constant_of<hmpc::statistical_security{PIA_MPC_STATISTICAL_SECURITY}>
        ) + ...);
    });

    auto tag = queue(
        x * alpha + r
    );

    queue.wait();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    fmt::print("{} {:2.10f}\n", n, duration.count());
}
