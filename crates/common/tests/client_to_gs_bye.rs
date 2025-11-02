use common::proto::ClientToGs;

#[test]
fn bye_roundtrips_with_bincode() {
    let msg = ClientToGs::Bye;
    let bytes = bincode::serialize(&msg).unwrap();
    let back: ClientToGs = bincode::deserialize(&bytes).unwrap();
    match back {
        ClientToGs::Bye => {}
        _ => panic!("expected Bye"),
    }
}
