// SPDX-License-Identifier: GPL-3.0-or-later
//
// Compile VerusHash 2.2 + blake2b for CPU Verus sweep; optional OpenCL link.
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest.parent().unwrap_or(manifest.as_path());
    let tp = repo.join("src").join("third_party");

    println!("cargo:rerun-if-changed=native/verus_ffi.c");
    println!("cargo:rerun-if-changed=native/verus_ffi.h");
    println!(
        "cargo:rerun-if-changed={}",
        tp.join("blake2b").join("blake2b.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        tp.join("verushash").join("verus_hash.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        tp.join("verushash").join("verus_clhash.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        tp.join("verushash").join("haraka_portable.c").display()
    );

    cc::Build::new()
        .file("native/verus_ffi.c")
        .file(tp.join("blake2b").join("blake2b.c"))
        .file(tp.join("verushash").join("verus_hash.c"))
        .file(tp.join("verushash").join("verus_clhash.c"))
        .file(tp.join("verushash").join("haraka_portable.c"))
        .include("native")
        .include(&tp)
        .include(tp.join("verushash"))
        .include(tp.join("blake2b"))
        .define("_GNU_SOURCE", None)
        .flag_if_supported("-std=c11")
        .flag_if_supported("-Wno-unused-parameter")
        .compile("mm_verus");

    #[cfg(all(feature = "gpu", target_os = "windows"))]
    {
        let libdir = manifest.join("third_party").join("opencl");
        if libdir.join("libOpenCL.a").is_file() {
            println!("cargo:rustc-link-search=native={}", libdir.display());
        } else {
            println!(
                "cargo:warning=pcminer: third_party/opencl/libOpenCL.a missing — GPU link may fail on MinGW"
            );
        }
    }
}
