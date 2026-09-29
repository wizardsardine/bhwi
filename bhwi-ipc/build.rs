fn main() {
    println!("cargo:rerun-if-changed=schema/bhwi.capnp");
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/bhwi.capnp")
        .run()
        .expect("compiling schema/bhwi.capnp requires the capnp binary");
}
