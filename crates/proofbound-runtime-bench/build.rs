fn main() {
    let profile = std::env::var("PROFILE").expect("Cargo supplies PROFILE to build scripts");
    println!("cargo:rustc-env=PBR_BENCH_BUILD_PROFILE={profile}");
}
