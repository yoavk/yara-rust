// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

use std::env;

fn main() {
    // Tell cargo to tell rustc to link the system yara
    // shared library.
    link("yara");

    // Add the environment variable YARA_LIBRARY_PATH to the library search path.
    if let Some(yara_library_path) = std::env::var("YARA_LIBRARY_PATH")
	.ok()
	.filter(|path| !path.is_empty())
    {
	println!("cargo:rustc-link-search=native={}", yara_library_path);
    }

    build::add_bindings();
}

fn link(lib: &str) {
    println!("cargo:rustc-link-lib={}={}", lib_mode(lib), lib);
}

fn lib_mode(lib: &str) -> &'static str {
    let kind = env::var(&format!("LIB{}_STATIC", lib.to_uppercase()));
    match kind.ok().as_deref() {
	Some("0") => "dylib",
	Some(_) => "static",
	None => "dylib",
    }
}

#[cfg(any(feature = "bundled-3_7",
	  feature = "bundled-3_11"))]
mod build {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    #[cfg(feature = "bundled-3_7")]
    const BINDING_FILE: &'static str = "yara-3.7.rs";

    #[cfg(feature = "bundled-3_11")]
    const BINDING_FILE: &'static str = "yara-3.11.rs";

    pub fn add_bindings() {
	let out_dir = env::var("OUT_DIR")
	    .expect("$OUT_DIR should be defined");
	let out_path = PathBuf::from(out_dir).join("bindings.rs");
	fs::copy(PathBuf::from("bindings").join(BINDING_FILE), out_path)
	    .expect("Could not copy bindings to output directory");
    }
}

#[cfg(not(any(feature = "bundled-3_7",
	      feature = "bundled-3_11")))]
mod build {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let mut builder = bindgen::Builder::default()
            .header("wrapper.h")
            .whitelist_var("CALLBACK_.*")
            .whitelist_var("ERROR_.*")
            .whitelist_var("META_TYPE_.*")
            .whitelist_var("STRING_GFLAGS_NULL")
            .whitelist_var("YARA_ERROR_LEVEL_.*")
            .whitelist_var("SCAN_FLAGS_.*")
            .whitelist_function("yr_initialize")
            .whitelist_function("yr_finalize")
            .whitelist_function("yr_finalize_thread")
            .whitelist_function("yr_compiler_.*")
            .whitelist_function("yr_rule_.*")
            .whitelist_function("yr_rules_.*")
            .whitelist_function("yr_get_tidx")
            .whitelist_type("YR_EXTERNAL_VARIABLE")
	    .whitelist_type("YR_MATCH")
            .opaque_type("YR_COMPILER")
            .opaque_type("YR_ARENA")
            .opaque_type("YR_AC_MATCH_TABLE")
            .opaque_type("YR_AC_TRANSITION_TABLE")
            .opaque_type("_YR_EXTERNAL_VARIABLE");

	if let Some(yara_include_dir) = env::var("YARA_INCLUDE_DIR")
	    .ok()
	    .filter(|dir| !dir.is_empty())
	{
	    builder = builder.clang_arg(format!("-I{}", yara_include_dir))
	}

	let bindings = builder
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
