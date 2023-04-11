use walkdir::WalkDir;

fn main() {
    std::fs::create_dir_all("gen/protos").unwrap();
    let proto_dirs = vec![
        "googleapis/google/cloud/secretmanager/v1",
        "googleapis/google/type",
    ];

    let mut proto_files = Vec::new();
    for proto_dir in proto_dirs {
        for entry in WalkDir::new(proto_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|e| e == "proto")
                    .unwrap_or_default()
            })
        {
            proto_files.push(entry.into_path());
        }
    }

    tonic_build::configure()
        .out_dir("gen/protos")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&proto_files, &["googleapis"])
        .unwrap();
}
