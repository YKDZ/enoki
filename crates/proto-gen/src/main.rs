use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let options = GeneratorOptions::from_args(env::args_os().skip(1))?;
    fs::create_dir_all(&options.out_dir).with_context(|| {
        format!(
            "failed to create Rust protobuf output directory {}",
            options.out_dir.display()
        )
    })?;

    let protoc = protoc_bin_vendored::protoc_bin_path()
        .context("failed to locate vendored protoc binary")?;
    // The generator is single-threaded and sets PROTOC immediately before
    // prost-build reads it.
    unsafe {
        env::set_var("PROTOC", protoc);
    }

    let mut config: prost_build::Config = prost_build::Config::new();
    config.out_dir(&options.out_dir);
    config.compile_protos(&[options.proto_file], &[options.proto_root])?;

    Ok(())
}

struct GeneratorOptions {
    proto_file: PathBuf,
    proto_root: PathBuf,
    out_dir: PathBuf,
}

impl GeneratorOptions {
    fn from_args(mut args: impl Iterator<Item = OsString>) -> Result<Self> {
        let proto_file = required_path_arg(&mut args, "proto file")?;
        let proto_root = required_path_arg(&mut args, "proto root")?;
        let out_dir = required_path_arg(&mut args, "output directory")?;

        if let Some(extra) = args.next() {
            bail!("unexpected extra argument: {}", Path::new(&extra).display());
        }

        Ok(Self {
            proto_file,
            proto_root,
            out_dir,
        })
    }
}

fn required_path_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<PathBuf> {
    args.next()
        .map(PathBuf::from)
        .with_context(|| format!("missing {name} argument"))
}
