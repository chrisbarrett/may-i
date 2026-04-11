use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn parse_never_panics(input in any::<String>()) {
        let _ = crate::parse(&input);
    }
}
