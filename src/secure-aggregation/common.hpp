#pragma once

#include <hmpc/comp/accessor.hpp>
#include <hmpc/comp/tensor.hpp>
#include <hmpc/comp/queue.hpp>
#include <hmpc/detail/unique_tag.hpp>
#include <hmpc/expr/abs.hpp>
#include <hmpc/expr/binary_expression.hpp>
#include <hmpc/expr/bit_monomial.hpp>
#include <hmpc/expr/cast.hpp>
#include <hmpc/expr/crypto/lhe/enc.hpp>
#include <hmpc/expr/crypto/lhe/dec.hpp>
#include <hmpc/expr/crypto/cipher.hpp>
#include <hmpc/expr/constant.hpp>
#include <hmpc/expr/matrix_vector_product.hpp>
#include <hmpc/expr/mpc/share.hpp>
#include <hmpc/expr/number_theoretic_transform.hpp>
#include <hmpc/expr/random/binomial_from_number_generator.hpp>
#include <hmpc/expr/random/uniform_from_number_generator.hpp>
#include <hmpc/expr/tensor.hpp>
#include <hmpc/expr/reduce.hpp>
#include <hmpc/expr/unsqueeze.hpp>
#include <hmpc/expr/vector.hpp>
#include <hmpc/ints/literals.hpp>
#include <hmpc/ints/poly_mod.hpp>
#include <hmpc/net/queue.hpp>

#include <fmt/format.h>

#include <charconv>
#include <chrono>
#include <ranges>
#include <string>
#include <vector>

namespace hmpc::comp
{
    namespace bgv = hmpc::comp::crypto::lhe;
}
namespace hmpc::expr
{
    namespace bgv = hmpc::expr::crypto::lhe;
}

using namespace hmpc::ints::literals;
using namespace hmpc::expr::operators;
using namespace hmpc::iter;
namespace expr = hmpc::expr;
namespace ints = hmpc::ints;
namespace comm = hmpc::net;
namespace comp = hmpc::comp;
using hmpc::detail::unique_tag;

#ifdef PIA_MPC_COMPUTE_PARTIES
constexpr auto compute_parties = comm::communicator_for<PIA_MPC_COMPUTE_PARTIES>;
#else
constexpr auto compute_parties = comm::communicator_for<0, 1, 2, 3>;
#endif
#ifdef PIA_MPC_INPUT_PARTIES
constexpr auto input_parties = comm::communicator_for<PIA_MPC_INPUT_PARTIES>;
#else
constexpr auto input_parties = comm::communicator_for<4, 5, 6, 7>;
#endif
constexpr auto all_parties = compute_parties.append(input_parties);
constexpr auto all_party_count = all_parties.size;
constexpr auto all_party_count_constant = hmpc::size_constant_of<all_parties.size>;
constexpr auto party_count = compute_parties.size;
constexpr auto party_count_constant = hmpc::size_constant_of<party_count>;
constexpr auto input_party_count = input_parties.size;
constexpr auto input_party_count_constant = hmpc::size_constant_of<input_party_count>;
#ifdef PIA_MPC_PARTY_ID
constexpr auto id = hmpc::party_constant_of<PIA_MPC_PARTY_ID>;
#else
constexpr auto id = hmpc::party_constant_of<0>;
#endif

constexpr auto config = "config/mpc.yaml";

constexpr auto p = 0x8822'd806'2332'0001_int; // 9809640459238244353
constexpr auto q = 0x5'91f5'b834'c0d96'1f67'343b'cc89'02bd'eda2'771f'5430'6ff1'5116'2ff8'd2b4'0f41'94dc'0001_int; // 676310504550516370745208338938566342426856908484397554505023779011987369401721290753
constexpr auto N = hmpc::size{1} << 16;
constexpr auto bound = hmpc::constant_of<0x2a8af94f7f989c000000000000000000280000_int>;
constexpr auto statistical_security = hmpc::constant_of<hmpc::statistical_security{64}>;
constexpr auto zeroknowledge_security = hmpc::constant_of<hmpc::statistical_security{128}>;
constexpr auto U = hmpc::size_constant_of<16>;
constexpr auto V = hmpc::size_constant_of<8>;

using Rq = ints::poly_mod<q, N, ints::coefficient_representation>;
using ntt_Rq = ints::traits::number_theoretic_transform_type_t<Rq>;
using mod_q = Rq::element_type;

using Rp = ints::poly_mod<p, N, ints::coefficient_representation>;
using ntt_Rp = ints::traits::number_theoretic_transform_type_t<Rp>;
using mod_p = Rp::element_type;
using mod_p_shares = comp::mpc::shares<mod_p, PIA_MPC_COMPUTE_PARTIES>;

using plaintext = ntt_Rp;
using plaintext_shares = comp::mpc::shares<plaintext, PIA_MPC_COMPUTE_PARTIES>;

constexpr auto p_value = expr::constant_of<mod_q{p}>;

template<typename, typename T>
using second_type = T;

template<typename T, typename U>
constexpr auto&& second(T&&, U&& second) noexcept
{
    return std::forward<U>(second);
}

auto parse_args(int argc, char** raw_argv)
{
    std::vector<std::string_view> argv(raw_argv, raw_argv + argc);

    hmpc::size n = 100;
    if (argc > 1)
    {
        std::from_chars(argv[1].data(), argv[1].data() + argv[1].size(), n);
    }
    int processors = 0;
    if (argc > 2)
    {
        std::from_chars(argv[2].data(), argv[2].data() + argv[2].size(), processors);
    }

    return std::pair(hmpc::shape{n}, processors);
}

auto start()
{
    return std::chrono::high_resolution_clock::now();
}

auto time(auto start, std::string_view context)
{
    auto now = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = now - start;
    fmt::print("[Party {}, {}]\t{:2.10f}\n", id.value, context, duration.count());
}

auto time(auto start, auto& queue, std::string_view context)
{
    // Make sure that all scheduled computations are done.
    // This is done in the demo, so computations do not happen in parallel to the network operations.
    // In real applications there is no need to do this.
    queue.wait();
    time(start, context);
}

template<auto Tag = []{}, typename Tensors>
constexpr auto as_expr(Tensors& tensors) noexcept
{
    constexpr auto n = std::tuple_size_v<Tensors>;
    return for_packed_range<n>([&](auto... i)
    {
        if constexpr (requires { std::get<0>(std::get<0>(tensors)); })
        {
            return std::make_tuple(as_expr<unique_tag(Tag, i)>(std::get<i>(tensors))...);
        }
        else if constexpr (requires { expr::bgv::ciphertext(std::get<0>(tensors)); })
        {
            return std::make_tuple(expr::bgv::ciphertext<unique_tag(Tag, i)>(std::get<i>(tensors))...);
        }
        else if constexpr (requires { expr::bgv::key(std::get<0>(tensors)); })
        {
            return std::make_tuple(expr::bgv::key<unique_tag(Tag, i)>(std::get<i>(tensors))...);
        }
        else
        {
            return std::make_tuple(expr::tensor<unique_tag(Tag, i)>(std::get<i>(tensors))...);
        }
    });
}

template<typename Expressions>
constexpr auto sum(Expressions exprs) noexcept
{
    constexpr auto n = std::tuple_size_v<Expressions>;
    return for_packed_range<n>([&](auto... i)
    {
        if constexpr (n == 1)
        {
            return std::get<0>(exprs);
        }
        else
        {
            return (std::get<i>(exprs) + ...);
        }
    });
}

template<typename Left, typename Right>
constexpr auto add(Left left, Right right) noexcept
{
    static_assert(std::tuple_size_v<Left> == std::tuple_size_v<Right>);
    constexpr auto n = std::tuple_size_v<Left>;
    return for_packed_range<n>([&](auto... i)
    {
        return std::make_tuple(std::get<i>(left) + std::get<i>(right)...);
    });
}

template<typename Left, typename Right>
constexpr auto mul_scalar(Left left, Right right) noexcept
{
    constexpr auto n = std::tuple_size_v<Right>;
    return for_packed_range<n>([&](auto... i)
    {
        return std::make_tuple(left * std::get<i>(right)...);
    });
}

template<typename Left, typename Right>
constexpr auto equal_ciphertexts(Left left, Right right) noexcept
{
    static_assert(std::tuple_size_v<Left> == std::tuple_size_v<Right>);
    constexpr auto n = std::tuple_size_v<Left>;
    return for_packed_range<n>([&](auto... i)
    {
        return (
            expr::all(std::get<i>(left) == std::get<i>(right))
            bitand ...
        );
    });
}

using rng = hmpc::default_random_engine;
using prf_key_type = hmpc::core::limb_array<rng::key_size, rng::value_type>;
using prg_key_type = prf_key_type;
using cipher_type = hmpc::core::limb_array<rng::key_size + rng::nonce_size, rng::value_type>;

/// for this demo, the prf key is i
constexpr auto get_prf_key(auto i) noexcept
{
    using limb_type = rng::value_type;
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> storage = {hmpc::constant_cast<limb_type>(i)};
    return storage.span(hmpc::access::read);
}

// for this demo, same as prf key
constexpr auto get_prg_key(auto i) noexcept
{
    return get_prf_key(i);
}

constexpr auto get_prf_keys() noexcept
{
    return for_packed_range<party_count>([&](auto... i)
    {
        return std::make_tuple(
            get_prf_key(i)...
        );
    });
}

// for this demo, same as prf key
constexpr auto get_prg_keys() noexcept
{
    return get_prf_keys();
}

// for this demo, the mac key is deterministically derived from a prf key with value 42 and nonce i
constexpr auto generate_mac_share(auto i) noexcept
{
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> key = {42};
    return expr::mpc::share(
        expr::random::uniform<mod_p>(
            expr::random::number_generator(
                key.span(hmpc::access::read),
                hmpc::index{hmpc::constant_cast<hmpc::size>(i)},
                hmpc::shape{party_count_constant}
            ),
            hmpc::shape{},
            statistical_security
        ),
        i,
        compute_parties
    );
}

constexpr auto generate_mac_randomness_share(auto prf_key, auto sender, auto receiver, auto const& shape) noexcept
{
    return expr::random::uniform<plaintext>(
        expr::random::number_generator(
            prf_key,
            hmpc::index{hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
            hmpc::shape{party_count_constant, input_party_count_constant}
        ),
        shape,
        statistical_security
    );
}

constexpr auto generate_mac_randomness(auto prf_keys, auto sender, auto receiver, auto const& shape) noexcept
{
    return for_packed_range<party_count>([&](auto... j)
    {
        return (generate_mac_randomness_share(
            std::get<j>(prf_keys),
            sender,
            receiver,
            shape
        ) + ...);
    });
}

constexpr auto generate_input_mac_randomness(auto prf_keys, auto sender, auto const& shape) noexcept
{
    return for_packed_range<input_party_count>([&](auto... j)
    {
        return std::make_tuple(
            generate_mac_randomness(prf_keys, sender, j, shape)...
        );
    });
}

constexpr auto tag(auto mac_key, auto share, auto randomness) noexcept
{
    return mac_key * share.value + randomness;
}

// for this demo, the share is deterministically derived from a prf key with value 44 and nonce `sender`
constexpr auto generate_input(auto sender, auto const& shape) noexcept
{
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> storage = {44};
    auto key = storage.span(hmpc::access::read);
    return expr::random::uniform<plaintext>(
        expr::random::number_generator(
            key,
            hmpc::index{hmpc::constant_cast<hmpc::size>(sender)},
            hmpc::shape{input_party_count_constant}
        ),
        shape,
        statistical_security
    );
}

constexpr auto generate_mac_shares() noexcept
{
    return for_packed_range<party_count>([&](auto... i)
    {
        return expr::mpc::shares(
            generate_mac_share(compute_parties.get(i))...
        );
    });
}

constexpr auto generate_mac_key() noexcept
{
    return generate_mac_shares().reconstruct();
}

// for this demo, the share is deterministically derived from a prf key with value 43 and nonce `(sender, receiver)`
constexpr auto generate_share(auto sender, auto receiver, auto const& shape) noexcept
{
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> key = {43};
    return expr::mpc::share(
        expr::random::uniform<plaintext>(
            expr::random::number_generator(
                key.span(hmpc::access::read),
                hmpc::index{hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
                hmpc::shape{party_count_constant, input_party_count_constant}
            ),
            shape,
            statistical_security
        ),
        sender,
        compute_parties
    );
}

// for this demo, the keys are deterministically derived from a prg key with value 44
constexpr auto get_encryption_prg() noexcept
{
    static constexpr hmpc::core::limb_array<rng::key_size, rng::value_type> key_storage = {44};
    return key_storage.span(hmpc::access::read);
}

auto get_private_key(auto /* i */)
{
    constexpr auto rand_count = hmpc::constants::six;

    auto prg_key = get_encryption_prg();

    return expr::number_theoretic_transform(
        expr::random::centered_binomial<Rq>(
            expr::random::number_generator(
                prg_key,
                hmpc::index{hmpc::constants::zero, hmpc::constants::zero, hmpc::constants::zero}, // s from nonce 0
                hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
            ),
            hmpc::shape{},
            hmpc::constants::half
        )
    );
}

auto get_public_key(auto i) noexcept
{
    constexpr auto rand_count = hmpc::constants::six;

    auto prg_key = get_encryption_prg();

    auto a = expr::random::uniform<ntt_Rq>(
        expr::random::number_generator(
            prg_key,
            hmpc::index{hmpc::constants::one, hmpc::constants::zero, hmpc::constants::zero}, // a from nonce 1
            hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
        ),
        hmpc::shape{},
        statistical_security
    );
    auto s = get_private_key(i);
    auto e = expr::number_theoretic_transform(
        expr::random::centered_binomial<Rq>(
            expr::random::number_generator(
                prg_key,
                hmpc::index{hmpc::constants::two, hmpc::constants::zero, hmpc::constants::zero}, // e from nonce 2
                hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
            ),
            hmpc::shape{},
            hmpc::constants::ten
        )
    );

    auto b = a * s + p_value * e;

    return expr::bgv::key_expression{a, b};
}

auto encrypt(auto sender, auto receiver, auto message)
{
    auto rand0 = hmpc::constants::three;
    auto rand1 = hmpc::constants::four;
    auto rand2 = hmpc::constants::five;
    auto rand_count = hmpc::constants::six;

    auto prg_key = get_encryption_prg();
    auto k = get_public_key(sender);

    auto rng_u = expr::random::number_generator(
        prg_key,
        hmpc::index{rand0, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );
    auto rng_v = expr::random::number_generator(
        prg_key,
        hmpc::index{rand1, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );
    auto rng_w = expr::random::number_generator(
        prg_key,
        hmpc::index{rand2, hmpc::constant_cast<hmpc::size>(sender), hmpc::constant_cast<hmpc::size>(receiver)},
        hmpc::shape{rand_count, party_count_constant, input_party_count_constant}
    );

    return expr::bgv::enc(
        k,
        message,
        expr::bgv::randomness<ntt_Rq>(
            message.shape(),
            hmpc::constants::half, // variance u
            hmpc::constants::ten, // variance v
            hmpc::constants::ten, // variance w
            rng_u,
            rng_v,
            rng_w
        )
    );
}

// in a real protocol, this would be generated from a random oracle or interactively
auto challenge_matrix(auto const& matrix_shape)
{
    constexpr auto bit_size = hmpc::core::limb_traits<hmpc::size>::bit_size;
    using uint = ints::ubigint<bit_size>;
    constexpr auto N0 = ints::num::bit_copy<uint>(hmpc::core::size_limb_span<hmpc::default_limb>(N));
    constexpr auto N1 = N0 + ints::one<>;
    using mod_N1 = ints::mod<N1>;
    auto rng = hmpc::random::compiletime_number_generator();
    auto w = comp::make_tensor<std::optional<hmpc::size>>(matrix_shape);
    for (comp::host_accessor access(w, hmpc::access::discard_write); auto i : std::views::iota(hmpc::size{0}, matrix_shape.size()))
    {
        auto mod = hmpc::random::uniform<mod_N1>(rng, statistical_security);
        auto x = ints::num::bit_copy<typename mod_N1::unsigned_type>(mod);
        if (x > N0)
        {
            access[i] = std::nullopt;
        }
        else
        {
            static_assert(N < (hmpc::size{1} << hmpc::default_limb::bit_size));
            access[i] = static_cast<hmpc::size>(x.data[0]);
        }
    }
    return w;
}

auto zk(auto& run, auto key, auto x)
{
    auto shape = x.shape();
    static_assert(shape.get(hmpc::size_constant_of<shape.rank - 1>) == U);
    auto aux_shape = hmpc::unsqueeze(hmpc::squeeze(shape, hmpc::constants::minus_one, hmpc::force), hmpc::constants::minus_one, V);
    auto matrix_shape = hmpc::unsqueeze(shape, hmpc::constants::minus_two, V);

    auto r = expr::bgv::randomness<ntt_Rq>(shape);
    auto c = expr::bgv::enc(key, x, r);
    auto y = expr::random::drown_signed_uniform<Rq>(aux_shape, mod_p::half_modulus_constant, zeroknowledge_security);
    auto s = expr::number_theoretic_transform(
        expr::bgv::randomness_expression(
            expr::random::drown_signed_uniform<Rq>(
                aux_shape,
                hmpc::random::centered_binomial_limits<hmpc::rational_size{1, 2}>::max,
                zeroknowledge_security
            ),
            expr::random::drown_signed_uniform<Rq>(
                aux_shape,
                hmpc::random::centered_binomial_limits<hmpc::size{10}>::max,
                zeroknowledge_security
            ),
            expr::random::drown_signed_uniform<Rq>(
                aux_shape,
                hmpc::random::centered_binomial_limits<hmpc::size{10}>::max,
                zeroknowledge_security
            )
        )
    );
    auto a = expr::bgv::enc(key, y, s);

    auto w = challenge_matrix(matrix_shape);
    auto W = expr::bit_monomial<N>(expr::tensor(w));

    auto z = y + expr::matrix_vector_product(W, expr::cast<Rq>(expr::inverse_number_theoretic_transform(x)));
    auto t = expr::bgv::randomness_expression(
        expr::inverse_number_theoretic_transform(s.u) + expr::matrix_vector_product(W, expr::inverse_number_theoretic_transform(r.u)),
        expr::inverse_number_theoretic_transform(s.v) + expr::matrix_vector_product(W, expr::inverse_number_theoretic_transform(r.v)),
        expr::inverse_number_theoretic_transform(s.w) + expr::matrix_vector_product(W, expr::inverse_number_theoretic_transform(r.w))
    );

    return run(c, a, z, t);
}

auto verify_zk(auto& run, auto key, auto c, auto a, auto z, auto t)
{
    auto shape = c.c0.shape();
    static_assert(shape.get(hmpc::size_constant_of<shape.rank - 1>) == U);
    auto matrix_shape = hmpc::unsqueeze(shape, hmpc::constants::minus_two, V);

    auto norm = [](auto x)
    {
        static_assert(decltype(x)::value_type::representation == ints::coefficient_representation);

        return expr::abs(
            expr::cast<typename Rq::signed_type>(x)
        );
    };

    auto vec = [](auto c)
    {
        return expr::unsqueeze(
            expr::unsqueeze(
                expr::vectorize<N>(
                    expr::constant(c)
                ),
                hmpc::constants::minus_one
            ),
            hmpc::constants::minus_one
        );
    };

    auto w = challenge_matrix(matrix_shape);
    auto W = expr::bit_monomial<N>(expr::tensor(w));

    auto d = expr::bgv::enc(key, expr::number_theoretic_transform(z), expr::number_theoretic_transform(t));
    auto check = expr::all(
        d == expr::bgv::ciphertext_expression(
            a.c0 + expr::number_theoretic_transform(expr::matrix_vector_product(W, expr::inverse_number_theoretic_transform(c.c0))),
            a.c1 + expr::number_theoretic_transform(expr::matrix_vector_product(W, expr::inverse_number_theoretic_transform(c.c1)))
        )
    ) bitand
    expr::all(
        norm(z) <= vec(
            hmpc::core::shift_left(
                mod_p::modulus_constant,
                hmpc::constant_cast<hmpc::size>(zeroknowledge_security)
            )
        )
    ) bitand
    expr::all(
        norm(t.u) <= vec(
            hmpc::core::shift_left(
                hmpc::random::centered_binomial_limits<hmpc::rational_size{1, 2}>::max,
                hmpc::core::add(
                    hmpc::constant_cast<hmpc::size>(zeroknowledge_security),
                    hmpc::constants::one
                )
            )
        )
    ) bitand
    expr::all(
        norm(t.v) <= vec(
            hmpc::core::shift_left(
                hmpc::random::centered_binomial_limits<hmpc::size{10}>::max,
                hmpc::core::add(
                    hmpc::constant_cast<hmpc::size>(zeroknowledge_security),
                    hmpc::constants::one
                )
            )
        )
    ) bitand
    expr::all(
        norm(t.w) <= vec(
            hmpc::core::shift_left(
                hmpc::random::centered_binomial_limits<hmpc::size{10}>::max,
                hmpc::core::add(
                    hmpc::constant_cast<hmpc::size>(zeroknowledge_security),
                    hmpc::constants::one
                )
            )
        )
    );
    return run(check);
}
