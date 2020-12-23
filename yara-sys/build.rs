// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

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

    let out_dir = env::var("OUT_DIR")
	.expect("$OUT_DIR should be defined");
    let out_path = PathBuf::from(out_dir).join("bindings.rs");

    build::add_bindings(&out_path);

    let major_version = parse_major_version(&out_path);
    println!("cargo:rustc-cfg=yara_major=\"{}\"", major_version);
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

/// Searches for "pub const YR_MAJOR_VERSION: u32 = " in the binding `file`.
// TODO: Find a better way to get the major version
fn parse_major_version(file: &Path) -> u32 {
    use std::io::{BufRead as _, BufReader};

    let line_begin = "pub const YR_MAJOR_VERSION: u32 = ";

    let file = File::open(file)
        .expect("Should be readable");

    let line = BufReader::new(file)
        .lines()
        .map(|r| r.expect("Should read lines"))
        .find(|l| l.starts_with(line_begin))
        .expect("There should be a major version defined");

    line.strip_prefix(line_begin)
        .expect("Should begin with line_begin")
        .strip_suffix(";")
        .expect("Should end with a ;")
        .parse()
        .expect("Should be able to parse the major version")
}

#[cfg(any(feature = "bundled-3_7",
	  feature = "bundled-3_11"))]
mod build {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[cfg(feature = "bundled-3_7")]
    const BINDING_FILE: &'static str = "yara-3.7.rs";

    #[cfg(feature = "bundled-3_11")]
    const BINDING_FILE: &'static str = "yara-3.11.rs";

    pub fn add_bindings(out_path: &Path) {
	fs::copy(PathBuf::from("bindings").join(BINDING_FILE), out_path)
	    .expect("Could not copy bindings to output directory");
    }
}

#[cfg(not(any(feature = "bundled-3_7",
	      feature = "bundled-3_11")))]
mod build {
    extern crate bindgen;

    use std::env;
    use std::path::Path;

    pub fn add_bindings(out_path: &Path) {
        let mut builder = bindgen::Builder::default()
            .header("wrapper.h")
            .whitelist_var("CALLBACK_.*")
            .whitelist_var("ERROR_.*")
            .whitelist_var("META_TYPE_.*")
            .whitelist_var("STRING_GFLAGS_NULL")
            .whitelist_var("YARA_ERROR_LEVEL_.*")
            .whitelist_var("SCAN_FLAGS_.*")
            .whitelist_var("YR_MAJOR_VERSION")
            .whitelist_var("YR_MINOR_VERSION")
            .whitelist_function("yr_initialize")
            .whitelist_function("yr_finalize")
            .whitelist_function("yr_finalize_thread")
            .whitelist_function("yr_compiler_.*")
            .whitelist_function("yr_rule_.*")
            .whitelist_function("yr_rules_.*")
            .whitelist_function("yr_get_tidx")
            .whitelist_type("YR_EXTERNAL_VARIABLE")
	    .whitelist_type("YR_MATCH")
            .whitelist_type("YR_ARENA")
            .opaque_type("YR_COMPILER")
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

        bindings
            .write_to_file(out_path)
            .expect("Couldn't write bindings!");
    }
}
