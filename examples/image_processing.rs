use image::codecs::png::PngEncoder;
use image::io::Reader as ImageReader;
use image::{DynamicImage, GrayImage, ImageBuffer, ImageOutputFormat, Luma, Pixels};
use itertools::Itertools;
use phantom_zone::{
    aggregate_server_key_shares, gen_client_key, gen_server_key_share, set_common_reference_seed,
    set_parameter_set, ClientKey, Encryptor, FheUint8, KeySwitchWithId, MultiPartyDecryptor,
    SampleExtractor, SeededBatchedFheUint8,
};
use rand::{thread_rng, Rng, RngCore};
use std::io::{BufRead, Cursor};
use std::ops::Sub;
use std::path::PathBuf;
use std::{fs, io};

fn read_image(path: PathBuf) -> (Vec<u8>, u32, u32) {
    dbg!(path.clone());
    let image = ImageReader::open(path).expect("Failed to read the file");
    let image_buffer = image.decode().expect("Decoding error");

    let (height, width) = (image_buffer.height(), image_buffer.width());

    let pixels = image_buffer
        .to_luma8()
        .pixels()
        .map(|&value| value.0[0])
        .collect();
    (pixels, height, width)
}

fn encrypt_image(key: &ClientKey, image_bytes: &[u8]) -> SeededBatchedFheUint8<Vec<u64>, [u8; 32]> {
    key.encrypt(image_bytes)
}

fn negative_image_fhe(encrypted_bytes: &[FheUint8]) -> Vec<FheUint8> {
    let negated_encrypted_image = encrypted_bytes
        .iter()
        .enumerate()
        .map(|(i, encrypted_byte)| {
            let now = std::time::Instant::now();
            let res = !encrypted_byte;
            println!("Byte: {}  FHE evaluation time: {:?}", i, now.elapsed());
            res
        })
        .collect();
    negated_encrypted_image
}

fn negative_image(bytes: &[u8]) -> Vec<u8> {
    dbg!(bytes.len());
    let inverted_bytes = bytes.iter().copied().map(|byte| 255 - byte).collect();
    inverted_bytes
}

fn regenerate_image(bytes: Vec<u8>, width: u32, height: u32, is_fhe: bool) {
    dbg!(bytes.len());
    let img_buff: ImageBuffer<Luma<u8>, Vec<_>> =
        ImageBuffer::from_vec(width, height, bytes).expect("Failed to re-generate the image");

    if is_fhe {
        img_buff
            .save("result_fhe.png")
            .expect("Error writing the new image")
    } else {
        img_buff
            .save("result.png")
            .expect("Error writing the new image")
    }
}

fn main() {
    let stdin = io::stdin();
    let mut filename = String::new();
    stdin
        .lock()
        .read_line(&mut filename)
        .expect("error reading cli");

    let mut path = std::env::current_dir().unwrap();
    path.extend(&[filename.trim()]);

    let (mut bytes, height, width) = read_image(path);
    let bytes_negated = negative_image(&bytes);

    regenerate_image(bytes_negated, width, height, false);

    set_parameter_set(phantom_zone::ParameterSelector::NonInteractiveLTE2Party);

    // set application's common reference seed
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    set_common_reference_seed(seed);

    let no_of_parties = 2;

    // Clide side //

    // Generate client keys
    let cks = (0..no_of_parties).map(|_| gen_client_key()).collect_vec();

    // client 0 encrypts its private inputs
    // Clients encrypt their private inputs in a seeded batched ciphertext using
    // their private RLWE secret `u_j`.

    let enc_input = encrypt_image(&cks[0], &bytes);

    // Clients independently generate their server key shares
    //
    // We assign user_id 0 to client 0, user_id 1 to client 1, user_id 2 to client
    // 2, user_id 3 to client 3.
    //
    // Note that `user_id`s must be unique among the clients and must be less than
    // total number of clients.
    let server_key_shares = cks
        .iter()
        .enumerate()
        .map(|(id, k)| gen_server_key_share(id, no_of_parties, k))
        .collect_vec();

    // Each client uploads their server key shares and encrypted private inputs to
    // the server in a single shot message.

    // Server side //

    // Server receives server key shares from each client and proceeds to aggregate
    // them to produce the server key. After this point, server can use the server
    // key to evaluate any arbitrary function on encrypted private inputs from
    // the fixed set of clients

    // aggregate server shares and generate the server key
    let server_key = aggregate_server_key_shares(&server_key_shares);
    server_key.set_server_key();

    // Server proceeds to extract private inputs sent by clients
    //
    // To extract client 0's (with user_id=0) private inputs we first key switch
    // client 0's private inputs from theit secret `u_j` to ideal secret of the mpc
    // protocol. To indicate we're key switching client 0's private input we
    // supply client 0's `user_id` i.e. we call `key_switch(0)`. Then we extract
    // the first ciphertext by calling `extract_at(0)`.
    //
    // Since client 0 only encrypts 1 input in batched ciphertext, calling
    // extract_at(index) for `index` > 0 will panic. If client 0 had more private
    // inputs then we can either extract them all at once with `extract_all` or
    // first `many` of them with `extract_many(many)`
    let encrypted_input = enc_input
        .unseed::<Vec<Vec<u64>>>()
        .key_switch(0)
        .extract_all();
    let negated_encrypted_bytes = negative_image_fhe(&encrypted_input);

    // each client produces decryption share
    let decryption_shares = negated_encrypted_bytes
        .iter()
        .map(|byte| {
            cks.iter()
                .map(|k| k.gen_decryption_share(byte))
                .collect_vec()
        })
        .collect_vec();

    // With all decryption shares, clients can aggregate the shares and decrypt the
    // ciphertext
    let out_bytes = negated_encrypted_bytes
        .iter()
        .zip(decryption_shares.iter())
        .map(|(byte, decryption_share)| cks[0].aggregate_decryption_shares(byte, decryption_share))
        .collect_vec();

    regenerate_image(out_bytes, width, height, true);
}
