use itertools::Itertools;
use phantom_zone::*;
use rand::{thread_rng, Rng, RngCore};
use std::ops::Sub;

const NUM_ROUNDS: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct FrogStats<T> {
    pub attack: T,
    pub defense: T,
    pub health: T,
}

impl<T> FrogStats<T> {
    fn health_mut(&mut self) -> &mut T {
        &mut self.health
    }
}

fn compute_round_damage(f1: &FrogStats<u8>, f2: &FrogStats<u8>) -> (bool, bool, bool, u8, u8) {
    // We first compute damages.
    let f1_damage_f2 = f1.attack - f2.defense;
    let f2_damage_f1 = f2.attack - f1.defense;

    // We check for possible faints.
    let f1_faints: bool = f2_damage_f1 >= f1.health;
    let f2_faints = f1_damage_f2 >= f2.health;

    // If both faint, result is a draw.
    let draw = f1_faints && f2_faints;
    let f2_wins = f1_faints && !f2_faints;
    let f1_wins = f2_faints && !f1_faints;

    (draw, f2_wins, f1_wins, f1_damage_f2, f2_damage_f1)
}

fn battle(f1: &mut FrogStats<u8>, f2: &mut FrogStats<u8>) -> (bool, bool, bool) {
    let mut round_finished = false;
    let mut is_draw = false;
    let mut is_f1_win = false;
    let mut is_f2_win = false;

    for _ in 0..NUM_ROUNDS {
        let (draw, f2_wins, f1_wins, f1_damage_f2, f2_damage_f1) = compute_round_damage(&f1, &f2);

        // We update the results vector depending on the result of `frogs_fainted`.
        // If a frog fainted this fight, we update `round_finished` and simply cancel
        // out any new updates to any of the fields.

        is_draw |= draw && !round_finished;
        is_f1_win |= f1_wins && !round_finished;
        is_f2_win |= f2_wins && !round_finished;

        let frogs_fainted = ((draw | f2_wins) | f1_wins) | round_finished;
        round_finished |= frogs_fainted;
        // We need to update frog's health to the new ones if none of them fainted this
        // round.
        let f1_damage_f2: u8 = f1_damage_f2 * u8::from(!frogs_fainted);
        let f2_damage_f1: u8 = f2_damage_f1 * u8::from(!frogs_fainted);

        // We apply damage and go for the next round.
        *f1.health_mut() -= f2_damage_f1;
        *f2.health_mut() -= f1_damage_f2;
    }

    (is_draw, is_f1_win, is_f2_win)
}

fn encrypt_frog_stats(
    key: &ClientKey,
    frog: FrogStats<u8>,
) -> SeededBatchedFheUint8<Vec<u64>, [u8; 32]> {
    // We add a zero to encrypt also a public value.
    key.encrypt(vec![frog.attack, frog.defense, frog.health, 0].as_slice())
}

fn compute_round_damage_fhe(
    f1: &FrogStats<FheUint8>,
    f2: &FrogStats<FheUint8>,
) -> (FheBool, FheBool, FheBool, FheUint8, FheUint8) {
    // We first compute damages.
    let f1_damage_f2 = f1.attack.sub(&f2.defense);
    let f2_damage_f1 = f2.attack.sub(&f1.defense);

    // We check for possible faints.
    let f1_faints: FheBool = f2_damage_f1.ge(&f1.health);
    let f2_faints = f1_damage_f2.ge(&f2.health);

    // If both faint, result is a draw.
    let draw = &f1_faints & &f2_faints;
    let f2_wins = &f1_faints & &(!(&f2_faints));
    let f1_wins = &f2_faints & &(!(&f1_faints));

    (draw, f2_wins, f1_wins, f1_damage_f2, f2_damage_f1)
}

fn fhe_battle(
    f1: &mut FrogStats<FheUint8>,
    f2: &mut FrogStats<FheUint8>,
    zero: FheUint8,
) -> (FheBool, FheBool, FheBool) {
    let mut round_finished = !(&zero.eq(&zero));
    let mut is_draw = round_finished.clone();
    let mut is_f1_win = round_finished.clone();
    let mut is_f2_win = round_finished.clone();

    for _ in 0..NUM_ROUNDS {
        let timer = std::time::Instant::now();
        let (draw, f2_wins, f1_wins, f1_damage_f2, f2_damage_f1) =
            compute_round_damage_fhe(&f1, &f2);
        println!("FHE round_damage {:?}", timer.elapsed());
        let timer2 = std::time::Instant::now();
        // We update the results vector depending on the result of `frogs_fainted`.
        // If a frog fainted this fight, we update `round_finished` and simply cancel
        // out any new updates to any of the fields.
        is_draw |= &draw & &(!(&round_finished));
        is_f1_win |= &f1_wins & &(!(&round_finished));
        is_f2_win |= &f2_wins & &(!(&round_finished));

        let frogs_fainted = &(&(&draw | &f2_wins) | &f1_wins) | &round_finished;
        round_finished |= frogs_fainted.clone();
        // We need to update frog's health to the new ones if none of them fainted this
        // round.
        let neg_frogs_fainted = !(&frogs_fainted);
        let f1_damage_f2_applied = &f2.health - &f1_damage_f2;
        let f2_damage_f1_applied = &f1.health - &f2_damage_f1;

        // We apply damage and go for the next round.
        *f1.health_mut() = f2_damage_f1_applied.mux(&f1.health, &neg_frogs_fainted);
        *f2.health_mut() = f1_damage_f2_applied.mux(&f2.health, &neg_frogs_fainted);
        println!("FHE round state updates {:?}", timer2.elapsed());
        println!("FHE total round {:?}", timer.elapsed());
    }

    (is_draw, is_f1_win, is_f2_win)
}

fn main() {
    let mut frog1 = FrogStats::<u8> {
        attack: 10,
        defense: 3,
        health: 5,
    };

    let mut frog2 = FrogStats::<u8> {
        attack: 5,
        defense: 9,
        health: 2,
    };

    let res = battle(&mut frog1, &mut frog2);
    dbg!(res);

    set_parameter_set(phantom_zone::ParameterSelector::NonInteractiveLTE2Party);

    // Let's start with actual FHE computation.
    // set application's common reference seed
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    set_common_reference_seed(seed);

    let no_of_parties = 2;

    // Clide side //

    // Generate client keys
    let cks = (0..no_of_parties).map(|_| gen_client_key()).collect_vec();

    // clients encrypt their frog stats.
    // Clients encrypt their private inputs in a seeded batched ciphertext using
    // their private RLWE secret `u_j`.
    let enc_frog_1 = encrypt_frog_stats(&cks[0], frog1);
    let enc_frog_2 = encrypt_frog_stats(&cks[1], frog2);

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
    let unseeded_frog_1 = enc_frog_1
        .unseed::<Vec<Vec<u64>>>()
        .key_switch(0)
        .extract_all();

    let zero = unseeded_frog_1[3].clone();

    let mut unseeded_frog_1 = FrogStats::<FheUint8> {
        attack: unseeded_frog_1[0].clone(),
        defense: unseeded_frog_1[1].clone(),
        health: unseeded_frog_1[2].clone(),
    };

    let unseeded_frog_2 = enc_frog_2
        .unseed::<Vec<Vec<u64>>>()
        .key_switch(1)
        .extract_all();

    let mut unseeded_frog_2 = FrogStats::<FheUint8> {
        attack: unseeded_frog_2[0].clone(),
        defense: unseeded_frog_2[1].clone(),
        health: unseeded_frog_2[2].clone(),
    };

    let battle_results = fhe_battle(&mut unseeded_frog_1, &mut unseeded_frog_2, zero);
    let battle_results = vec![battle_results.0, battle_results.1, battle_results.2];

    // each client produces decryption share
    let decryption_shares = battle_results
        .iter()
        .map(|bool| {
            cks.iter()
                .map(|k| k.gen_decryption_share(bool))
                .collect_vec()
        })
        .collect_vec();

    // With all decryption shares, clients can aggregate the shares and decrypt
    // the ciphertext
    let out_results = battle_results
        .iter()
        .zip(decryption_shares.iter())
        .map(|(bool, decryption_share)| cks[0].aggregate_decryption_shares(bool, decryption_share))
        .collect_vec();

    dbg!(out_results);
}
