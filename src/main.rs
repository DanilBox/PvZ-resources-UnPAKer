use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::{env, fs};

const ENCRYPTION_KEY: u8 = 0xF7;
const MAGIC: u32 = 0xBAC04AC0;
const VERSION: u32 = 0x0;
const FLAGS_END: u8 = 0x80;

struct PakReader {
    c: Cursor<Vec<u8>>,
}

impl PakReader {
    pub fn new(v: Vec<u8>) -> PakReader {
        return PakReader { c: Cursor::new(v) };
    }

    pub fn read_u8(&mut self) -> u8 {
        let mut buf = [0u8; 1];
        self.c.read_exact(&mut buf).expect("error from read u8");

        return u8::from_be_bytes(buf);
    }

    pub fn read_vec_u8(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.c.read_exact(&mut buf).expect("error from read vec u8");

        return buf;
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.c.read_exact(&mut buf).expect("error from read u32");
        buf.reverse();

        return u32::from_be_bytes(buf);
    }

    pub fn read_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.c.read_exact(&mut buf).expect("error from read u64");
        buf.reverse();

        return u64::from_be_bytes(buf);
    }

    pub fn read_string(&mut self, len: usize) -> String {
        let buf = self.read_vec_u8(len);
        let file_name = String::from_utf8(buf).expect("error from read string buffer");

        return file_name;
    }
}

struct PakRecord {
    file_path: String,
    file_size: u32,
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        panic!("arguments count is not equal to 3")
    }

    let pak_path = arguments.get(1).unwrap();
    let output_directory = arguments.get(2).unwrap();

    let mut pac = PakReader::new(read_buffer_from_file(pak_path));

    if MAGIC != pac.read_u32() {
        panic!("magic not equal")
    }

    if VERSION != pac.read_u32() {
        panic!("version not equal")
    }

    let mut records: Vec<PakRecord> = Vec::new();
    loop {
        if pac.read_u8() & FLAGS_END > 0 {
            break;
        }

        let name_length = pac.read_u8() as usize;
        let file_name = pac.read_string(name_length);

        let file_size = pac.read_u32();
        _ = pac.read_u64(); // windows timestamp

        let rec = PakRecord {
            file_path: file_name,
            file_size,
        };
        records.push(rec);
    }

    for rec in records {
        let size = rec.file_size as usize;
        let buf = pac.read_vec_u8(size);

        let file_path = rec.file_path.replace("\\", "/");
        let save_file_path = Path::new(&output_directory).join(file_path);

        let save_dir = save_file_path.parent().expect("error getting save folder");
        if !save_dir.exists() {
            fs::create_dir_all(save_dir).expect("error when creating save folder");
        }

        File::create(save_file_path)
            .expect("error when creating resource file")
            .write_all(&buf)
            .expect("error when writing to resource file")
    }

    println!("ok!")
}

fn read_buffer_from_file(pak_path: &String) -> Vec<u8> {
    let mut pak_file = File::open(pak_path).expect("pak file not found");

    let mut buffer = Vec::new();
    pak_file
        .read_to_end(&mut buffer)
        .expect("error read from file");

    return buffer.iter_mut().map(|el| *el ^ ENCRYPTION_KEY).collect();
}
