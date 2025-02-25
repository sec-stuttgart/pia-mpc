#include <hmpc/comp/accessor.hpp>
#include <hmpc/comp/tensor.hpp>
#include <hmpc/comp/queue.hpp>
#include <hmpc/expr/binary_expression.hpp>
#include <hmpc/expr/tensor.hpp>
#include <hmpc/expr/cast.hpp>
#include <hmpc/expr/constant.hpp>
#include <hmpc/expr/number_theoretic_transform.hpp>
#include <hmpc/expr/random/binomial_from_number_generator.hpp>
#include <hmpc/expr/random/uniform.hpp>
#include <hmpc/expr/random/uniform_from_number_generator.hpp>
#include <hmpc/expr/unsqueeze.hpp>
#include <hmpc/expr/value.hpp>
#include <hmpc/ints/poly_mod.hpp>
#include <hmpc/ints/literals.hpp>
#include <hmpc/random/binomial.hpp>
#include <hmpc/random/number_generator.hpp>

#include <fmt/format.h>
#include <sycl/sycl.hpp>

#include <charconv>
#include <chrono>

auto main(int argc, char** raw_argv) -> int
{
    using namespace hmpc::ints::literals;
    using namespace hmpc::expr::operators;
    constexpr auto q = PIA_MPC_CIPHERTEXT_MODULUS;
    constexpr hmpc::size N = 1 << PIA_MPC_LOG_N;
    using R = hmpc::ints::poly_mod<q, N, hmpc::ints::coefficient_representation>;
    using ntt_R = hmpc::ints::traits::number_theoretic_transform_type_t<R>;
    using mod_q = R::element_type;
    constexpr auto p = PIA_MPC_PLAINTEXT_MODULUS;
    using ntt_Rp = hmpc::ints::poly_mod<p, N, hmpc::ints::number_theoretic_transform_representation>;
    using mod_p = ntt_Rp::element_type;
    constexpr auto p_value = hmpc::expr::constant_of<mod_q{p}>;

    using rng = hmpc::default_random_engine;
    hmpc::core::limb_array<rng::key_size, rng::value_type> key_storage = {42};
    auto prg_key = key_storage.span(hmpc::access::read);
    auto prf_key = key_storage.span(hmpc::access::read);

    auto party_id = hmpc::size_constant_of<0>;
    auto party_count = hmpc::size_constant_of<2>;

    auto rand0 = hmpc::size_constant_of<0>;
    auto rand1 = hmpc::size_constant_of<1>;
    auto rand2 = hmpc::size_constant_of<2>;
    auto rand_count = hmpc::size_constant_of<3>;

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

    auto a_tensor = hmpc::comp::make_tensor<R>(hmpc::shape{});
    auto b_tensor = hmpc::comp::make_tensor<R>(hmpc::shape{});

    sycl_queue.submit([&](auto& handler)
    {
        hmpc::comp::device_accessor a(a_tensor, handler, hmpc::access::discard_write);
        hmpc::comp::device_accessor b(b_tensor, handler, hmpc::access::discard_write);

        handler.parallel_for(sycl::range{N}, [=](hmpc::size i)
        {
            a[i] = static_cast<mod_q>(hmpc::ints::ubigint<32>{argc + n + i});

            b[i] = static_cast<mod_q>(hmpc::ints::ubigint<32>{argc + N - i});
        });
    });
    auto [ntt_a, ntt_b, ntt_c0, ntt_c1] = queue(
        hmpc::expr::number_theoretic_transform(hmpc::expr::tensor(a_tensor)),
        hmpc::expr::number_theoretic_transform(hmpc::expr::tensor(b_tensor)),
        hmpc::expr::random::uniform<ntt_R>(hmpc::shape{n}),
        hmpc::expr::random::uniform<ntt_R>(hmpc::shape{n})
    );

    auto alpha = hmpc::expr::value(static_cast<mod_q>(mod_p{42_int}));

    queue.wait();
    auto start = std::chrono::high_resolution_clock::now();

    auto a = hmpc::expr::tensor(ntt_a);
    auto b = hmpc::expr::tensor(ntt_b);
    auto c0 = hmpc::expr::tensor(ntt_c0);
    auto c1 = hmpc::expr::tensor(ntt_c1);
    auto u = hmpc::expr::number_theoretic_transform(
        hmpc::expr::random::centered_binomial<R>(
            hmpc::expr::random::number_generator(prg_key, hmpc::index{rand0, party_id}, hmpc::shape{rand_count, party_count}),
            hmpc::shape{n},
            hmpc::constants::half
        )
    );
    auto v = hmpc::expr::number_theoretic_transform(
        hmpc::expr::random::drown_signed_uniform<R>(
            hmpc::expr::random::number_generator(prg_key, hmpc::index{rand1, party_id}, hmpc::shape{rand_count, party_count}),
            hmpc::shape{n},
            hmpc::constant_of<PIA_MPC_BOUND>,
            hmpc::constant_of<hmpc::statistical_security{PIA_MPC_STATISTICAL_SECURITY}>
        )
    );
    auto w = hmpc::expr::number_theoretic_transform(
        hmpc::expr::random::centered_binomial<R>(
            hmpc::expr::random::number_generator(prg_key, hmpc::index{rand2, party_id}, hmpc::shape{rand_count, party_count}),
            hmpc::shape{n},
            hmpc::constants::ten
        )
    );
    auto m = hmpc::expr::cast<ntt_R>(
        hmpc::expr::random::uniform<ntt_Rp>(
            hmpc::expr::random::number_generator(prf_key, hmpc::index{party_id}, hmpc::shape{party_count}),
            hmpc::shape{n},
            hmpc::constant_of<hmpc::statistical_security{PIA_MPC_STATISTICAL_SECURITY}>
        )
    );

    auto [drowned_c0, drowned_c1] = queue(
        c0 * alpha + hmpc::expr::unsqueeze(b, hmpc::constants::minus_one) * u + v * p_value + m,
        c1 * alpha + hmpc::expr::unsqueeze(a, hmpc::constants::minus_one) * u + w * p_value
    );

    queue.wait();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    fmt::print("{} {:2.10f}\n", N * n, duration.count());
}
