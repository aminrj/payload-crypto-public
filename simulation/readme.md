# TRANS3 — Virtual Lab Reference

## Lab Topology

The `setup_bridge_sim.sh` script creates a dual-bridge network using Linux network namespaces and virtual Ethernet pairs. The two bridge nodes are completely invisible (no IP address) and encrypt traffic on-the-fly.

```text
       (LAN Zone — Plaintext)              (WAN Zone — Encrypted)             (LAN Zone — Plaintext)

 ┌──────────────────────┐        ┌────────────────────────────────┐        ┌──────────────────────┐
 │      ns_host_a       │        │   ns_bridge1      ns_bridge2   │        │      ns_host_b       │
 │    (Source Client)   │        │  (Encryptor)     (Decryptor)   │        │ (Destination Server) │
 │                      │        │                                │        │                      │
 │ IP: 10.0.0.1/24      │        │ Bridge: br1        Bridge: br2 │        │ IP: 10.0.0.2/24      │
 │ MSS Clamping: 1428   │        │                                │        │ MSS Clamping: 1428   │
 └──────────┬───────────┘        └─────┬────────────────────┬─────┘        └──────────┬───────────┘
            │                          │                    │                         │
     [ MTU 1500 bytes ]         [ MTU 1550 ]         [ MTU 1550 ]             [ MTU 1500 bytes ]
            │                          │                    │                         │
        (veth-a0)                  (veth-a1)            (veth-c0)                 (veth-c1)
            │                          │                    │                         │
            ├────────(Link 1)──────────┤                    ├────────(Link 3)─────────┤
                                       │                    │
                                   (veth-b0)            (veth-b1)
                                       │                    │
                                       └───── (WAN Link) ───┘
                                       [  WIRETAPPED SEGMENT  ]
                                       [   MTU 1550 bytes     ]
```

---

## Packet Journey (A → B)

```
1. HOST A generates application data — max 1428 bytes (enforced by TCP MSS clamping).
2. HOST A builds an IP packet of up to 1500 bytes and sends it on veth-a0.
3. BRIDGE 1 receives the packet.
   → iptables intercepts outbound traffic toward veth-b0.
   → Calls xt_TRANS3 (--mode e).
   → Packet grows by 32 bytes (SEQ encrypted + MAC + RNONCE).
4. The encrypted packet (up to 1532 bytes) travels over the WAN link.
   → A passive attacker sniffing this segment sees only random bytes (XChaCha20).
5. BRIDGE 2 receives the encrypted packet.
   → iptables intercepts inbound traffic from veth-b1.
   → Calls xt_TRANS3 (--mode d).
   → Packet is authenticated (Poly1305 MAC), decrypted, and shrinks back by 32 bytes.
6. HOST B receives a perfectly restored plaintext packet.
```

---

## Cryptographic Transformation (xt_TRANS3)

### A. Original packet (plaintext)

```
┌────────┬────────┬──────────────────────────────────────────┐
│ IP hdr │ L4 hdr │ Payload (application data)               │
│  20 B  │  20 B  │ Up to 1428 bytes                         │
└────────┴────────┴──────────────────────────────────────────┘
```

### B. Encrypted packet on the WAN link

```
┌────────┬────────┬──────────────────────────────────────────┬────────┬────────┐
│ IP hdr │ L4 hdr │ Ciphertext (Payload + hidden SEQ 8B)     │ MAC    │ RNONCE │
│  20 B  │  20 B  │ Up to 1436 bytes                         │ 16 B   │  8 B   │
└────────┴────────┴──────────────────────────────────────────┴────────┴────────┘
                  |←────────────────────────────────────────→|
                         Encrypted by XChaCha20
                  |←─────────────────────────────────────────────────→|
                     Authenticated by Poly1305 MAC (including the
                     hidden AAD "NEGENCRY.TRANS3.V1", never sent)
                                                                      |
                     Sent in clear (pure random). Used to ────────────┘
                     derive the per-packet nonce for decryption.
```

---

## Three Engineering Pillars

The lab is tuned for multi-gigabit throughput by design:

1. **Asymmetric MTU**: LAN set to 1500, bridges to 1550 (Baby Jumbo Frames). This gives the bridge enough headroom to append the 32-byte TRANS3 overhead without triggering IP fragmentation.

2. **Multi-queue + RPS**: Virtual Ethernet cables are created with `numtxqueues 4 numrxqueues 4`. Combined with Receive Packet Steering (RPS), this allows all CPU cores to process packets in parallel while preserving order.

3. **Large TX queues + CUBIC**: `txqueuelen 10000` absorbs brief delays caused by cryptographic processing, preventing Tail Drop and protecting the TCP congestion window from collapse.

---

## Running the Tests

```bash
# 1. Start the simulation
sudo ./setup_bridge_sim.sh

# 2. Run the automated test suite
sudo ./test_bridge_sim.sh

# 3. Tear down when done
sudo ./setup_bridge_sim.sh --clean
```

The test suite covers:
- End-to-end ICMP connectivity
- 1 MB binary file transfer with SHA-256 integrity verification
- Wireshark captures at 3 simultaneous points (LAN A, WAN cable, LAN B)
- Cryptographic stealth test (plaintext must not appear on WAN)
- iperf3 throughput benchmark: encrypted vs. baseline
