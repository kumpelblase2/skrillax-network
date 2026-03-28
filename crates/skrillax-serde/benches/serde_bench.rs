use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Serialize, Deserialize, ByteSize, Debug, PartialEq)]
enum SubEnum {
    #[silkroad(value = 1)]
    VariantA(u32),
    #[silkroad(value = 2)]
    VariantB(String),
}

#[derive(Serialize, Deserialize, ByteSize, Debug, PartialEq)]
struct SubStruct {
    id: u64,
    name: String,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, ByteSize, Debug, PartialEq)]
struct NestedStruct {
    inner_struct: SubStruct,
    inner_enum: SubEnum,
    flags: Vec<bool>,
}

#[derive(Serialize, Deserialize, ByteSize, Debug, PartialEq)]
struct RootStruct {
    header: u32,
    items: Vec<NestedStruct>,
    footer: String,
}

fn bench_deserialization(c: &mut Criterion) {
    let data_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/data.bin");
    let items_count = 100;

    let mut file = File::open(&data_path).expect(
        "failed to open data file. Please run `cargo run --bin generate_bench_data --features \
         derive` first.",
    );
    let mut encoded_data = Vec::new();
    file.read_to_end(&mut encoded_data)
        .expect("failed to read data file");

    let mut cursor = std::io::Cursor::new(&encoded_data);
    let mut roots = Vec::with_capacity(items_count);
    for _ in 0..items_count {
        roots.push(RootStruct::read_from(&mut cursor).expect("failed to deserialize for setup"));
    }

    c.bench_function("deserialize_root_struct", |b| {
        b.iter(|| {
            let mut cursor = std::io::Cursor::new(&encoded_data);
            for _ in 0..items_count {
                black_box(RootStruct::read_from(&mut cursor)).expect("failed to deserialize");
            }
        })
    });

    c.bench_function("serialize_root_struct", |b| {
        let total_size: usize = roots.iter().map(|r| r.byte_size()).sum();
        let mut buffer = BytesMut::with_capacity(total_size);
        b.iter(|| {
            for root in &roots {
                black_box(root.write_to_end(&mut buffer));
            }
        })
    });
}

criterion_group!(benches, bench_deserialization);
criterion_main!(benches);
