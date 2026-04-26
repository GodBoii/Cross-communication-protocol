# CCP Protocol v0

## Constants

| Item | Value |
| --- | --- |
| Protocol | `ccp.v0` |
| UDP discovery port | `47827` |
| TCP session port | `47828` |
| Message encoding | UTF-8 JSON followed by `\n` |
| File chunk encoding | Base64 in JSON for v0 prototype |

## Discovery Packet

Discovery packets are UDP broadcast JSON objects:

```json
{
  "protocol": "ccp.v0",
  "type": "discovery",
  "device_id": "hex-sha256-id",
  "device_name": "Prajwal Windows",
  "platform": "windows",
  "tcp_port": 47828,
  "capabilities": ["file.transfer", "pairing"],
  "transports": {
    "wifi": { "available": true, "connected": true, "detail": "Wi-Fi adapter" },
    "lan": { "available": true, "connected": false, "detail": "Ethernet" },
    "usb": { "available": false, "connected": false, "detail": "Unavailable" },
    "bluetooth": { "available": true, "connected": false, "detail": "Bluetooth PAN" },
    "cloud": { "available": true, "connected": true, "detail": "Internet-capable network present" }
  },
  "endpoints": [
    { "transport": "wifi", "host": "192.168.1.25", "port": 47828 },
    { "transport": "lan", "host": "10.0.0.12", "port": 47828 }
  ],
  "timestamp": 1777200000
}
```

Notes:

- `transports` tells peers which connection families are currently detectable on the device.
- `endpoints` advertises concrete TCP routes the peer can try in priority order.
- v0 still transfers data over TCP sockets. A `bluetooth` or `usb` route is usable only when that transport exposes IP connectivity, such as PAN, tethering, or USB networking.

## Control Envelope

Every TCP control message uses this envelope:

```json
{
  "protocol": "ccp.v0",
  "id": "uuid",
  "type": "pair.request",
  "sender": {
    "device_id": "hex-sha256-id",
    "device_name": "Device Name",
    "platform": "android"
  },
  "payload": {},
  "timestamp": 1777200000
}
```

## Pairing

1. Sender connects to receiver TCP port.
2. Sender sends `pair.request` with a six digit `pair_code`.
3. Receiver prompts the user.
4. Receiver replies with `pair.response`.
5. Both sides store the peer if accepted.

### pair.request payload

```json
{
  "pair_code": "123456",
  "public_key": "reserved-for-v1"
}
```

### pair.response payload

```json
{
  "accepted": true,
  "reason": null
}
```

## File Transfer

### file.offer payload

```json
{
  "transfer_id": "uuid",
  "filename": "photo.jpg",
  "size": 1200344,
  "sha256": "hex",
  "chunk_size": 65536,
  "total_chunks": 19
}
```

### file.offer.response payload

```json
{
  "transfer_id": "uuid",
  "accepted": true,
  "resume_from": 0,
  "reason": null
}
```

### file.chunk payload

```json
{
  "transfer_id": "uuid",
  "index": 0,
  "sha256": "chunk-hex",
  "data_b64": "base64"
}
```

### file.complete payload

```json
{
  "transfer_id": "uuid",
  "sha256": "full-file-hex"
}
```

## Security Roadmap

The v0 local prototype is intentionally simple so the apps can connect quickly. Production security should add:

- Ed25519 device identity keys.
- X25519 session key exchange.
- TLS 1.3 or Noise protocol transport encryption.
- Signed messages.
- Trust store revocation.
- Permission-scoped feature grants per peer.
