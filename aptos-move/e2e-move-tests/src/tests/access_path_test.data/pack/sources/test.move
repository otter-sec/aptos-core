module 0x42.test {
    import 0x1.signer;

    struct Item has store { _dummy: bool }
    struct Cup<T> has store { _dummy: bool }
    struct Box<T> has key { _dummy: bool }

    public type_eq<T1: store, T2: store>(account: &signer): bool acquires Box {
        let sender: address;
        let r: bool;
        let b: bool;
    label b0:
        sender = signer.address_of(copy(account));
        move_to<Box<T1>>(move(account), Box<T1> { _dummy: false });
        r = exists<Box<T2>>(copy(sender));
        Box<T1> { _dummy: b } = move_from<Box<T1>>(move(sender));
        return move(r);
    }
}
