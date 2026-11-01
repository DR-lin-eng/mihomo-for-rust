use crate::{ByteWindow, PacketBuf};

#[test]
fn windows_share_the_same_storage() {
    let base = ByteWindow::freeze(vec![1, 2, 3, 4, 5]);
    let left = base.slice(0..2);
    let right = base.slice(2..5);
    assert_eq!(left.as_slice(), &[1, 2]);
    assert_eq!(right.as_slice(), &[3, 4, 5]);
}

#[test]
fn split_to_and_split_off_keep_views() {
    let mut base = ByteWindow::freeze(b"mihomo".to_vec());
    let head = base.split_to(3);
    let tail = base.split_off(1);
    assert_eq!(head.as_slice(), b"mih");
    assert_eq!(base.as_slice(), b"o");
    assert_eq!(tail.as_slice(), b"mo");
}

#[test]
fn packet_buf_carries_head_and_tail_room() {
    let packet = PacketBuf::new(ByteWindow::freeze(vec![9, 8, 7]), 32, 64);
    assert_eq!(packet.payload().as_slice(), &[9, 8, 7]);
    assert_eq!(packet.headroom(), 32);
    assert_eq!(packet.tailroom(), 64);
}
