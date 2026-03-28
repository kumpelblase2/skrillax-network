use bytes::BytesMut;
use rand::Rng;
use skrillax_serde::{ByteSize, Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
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

fn generate_random_root() -> RootStruct {
    let mut rng = rand::thread_rng();
    let items_count = rng.gen_range(5..15);
    let mut items = Vec::with_capacity(items_count);

    for _ in 0..items_count {
        let sub_struct = SubStruct {
            id: rng.gen(),
            name: (0..rng.gen_range(5..20))
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect(),
            data: (0..rng.gen_range(10..100)).map(|_| rng.gen()).collect(),
        };

        let sub_enum = if rng.gen_bool(0.5) {
            SubEnum::VariantA(rng.gen())
        } else {
            SubEnum::VariantB(
                (0..rng.gen_range(5..20))
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect(),
            )
        };

        let flags_count = rng.gen_range(1..10);
        let flags = (0..flags_count).map(|_| rng.gen()).collect();

        items.push(NestedStruct {
            inner_struct: sub_struct,
            inner_enum: sub_enum,
            flags,
        });
    }

    RootStruct {
        header: rng.gen(),
        items,
        footer: "END_OF_PACKET".to_string(),
    }
}

fn main() {
    let data_path = Path::new("crates/skrillax-serde/benches/data.bin");
    if data_path.exists() {
        println!("Data file already exists at {:?}", data_path);
        return;
    }

    let items_count = 100;
    let mut buffer = BytesMut::new();
    for _ in 0..items_count {
        let root = generate_random_root();
        root.write_to_end(&mut buffer);
    }

    let mut file = File::create(data_path).expect("failed to create data file");
    file.write_all(&buffer)
        .expect("failed to write data to file");
    println!("Generated benchmark data to {:?}", data_path);
}
