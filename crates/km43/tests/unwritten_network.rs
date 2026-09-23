//! An unwritten master can clear a foreign cache without inventing radio metadata.
use km43::{
    LinkEnvelope, LinkError, LinkField, LinkHeader, LinkMessageType, NetChange, NetConfigOp, ReqId,
    SessionId,
};

fn header() -> LinkHeader {
    LinkHeader {
        kind: LinkMessageType::NetConfig,
        session: SessionId::None,
        req_id: ReqId(1),
    }
}

/// cites: L-131, L-133, L-134
#[test]
fn l_133_unwritten_clear_has_only_op_and_zero_version() {
    let mut bytes = [0; 128];
    let len = NetChange::ClearUnwritten
        .write(header(), &mut bytes)
        .unwrap();
    let envelope = LinkEnvelope::decode(&bytes[..len]).unwrap();
    assert_eq!(envelope.keys(), 2);
    assert_eq!(NetChange::decode(envelope), Ok(NetChange::ClearUnwritten));
    for end in 0..len {
        assert!(
            NetChange::ClearUnwritten
                .write(header(), &mut bytes[..end])
                .is_err()
        );
    }
    let len = NetChange::ClearUnwritten
        .write(header(), &mut bytes)
        .unwrap();
    for end in 0..len {
        if let Ok(envelope) = LinkEnvelope::decode(&bytes[..end]) {
            assert!(NetChange::decode(envelope).is_err());
        }
    }
}

/// cites: L-131, L-133, L-134
#[test]
fn l_133_unwritten_clear_refuses_each_credential_and_metadata_key() {
    for (key, text, expected) in [
        (3, "foreign", LinkError::ClearCarriedCredentials),
        (4, "secret-passphrase", LinkError::ClearCarriedCredentials),
        (5, "CA", LinkError::UnwrittenClearCarriedMetadata),
        (6, "foreign-host", LinkError::UnwrittenClearCarriedMetadata),
    ] {
        let mut bytes = [0; 128];
        let mut cbor = header().write(3, &mut bytes).unwrap();
        cbor.key(1).unwrap();
        cbor.u64(u64::from(NetConfigOp::Clear as u8)).unwrap();
        cbor.key(2).unwrap();
        cbor.u64(0).unwrap();
        cbor.key(key).unwrap();
        cbor.text(text).unwrap();
        let len = cbor.finish().unwrap();
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
            Err(expected)
        );
    }
}

/// cites: L-133, L-135
#[test]
fn l_135_written_operations_cannot_use_zero_version() {
    let mut bytes = [0; 128];
    for change in [
        NetChange::Set {
            version: 0,
            ssid: "site",
            psk: "password",
            country: "CA",
            hostname: "unit",
        },
        NetChange::Clear {
            version: 0,
            country: "CA",
            hostname: "unit",
        },
    ] {
        assert_eq!(
            change.write(header(), &mut bytes),
            Err(LinkError::ZeroNetworkVersion)
        );
    }
    let mut cbor = header().write(2, &mut bytes).unwrap();
    cbor.key(1).unwrap();
    cbor.u64(u64::from(NetConfigOp::Set as u8)).unwrap();
    cbor.key(2).unwrap();
    cbor.u64(0).unwrap();
    let len = cbor.finish().unwrap();
    assert_eq!(
        NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
        Err(LinkError::ZeroNetworkVersion)
    );
}

/// cites: L-133, L-134, L-135
#[test]
fn l_135_written_clear_still_requires_both_metadata_fields() {
    for version in [1, u32::MAX] {
        let mut bytes = [0; 128];
        let clear = NetChange::Clear {
            version,
            country: "CA",
            hostname: "unit",
        };
        let len = clear.write(header(), &mut bytes).unwrap();
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
            Ok(clear)
        );
        for (present, missing) in [(5, LinkField::Hostname), (6, LinkField::Country)] {
            let mut cbor = header().write(3, &mut bytes).unwrap();
            cbor.key(1).unwrap();
            cbor.u64(u64::from(NetConfigOp::Clear as u8)).unwrap();
            cbor.key(2).unwrap();
            cbor.u64(u64::from(version)).unwrap();
            cbor.key(present).unwrap();
            cbor.text("CA").unwrap();
            let len = cbor.finish().unwrap();
            assert_eq!(
                NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
                Err(LinkError::Missing(missing))
            );
        }
    }
}

/// cites: L-133
#[test]
fn l_133_missing_version_is_not_an_unwritten_master() {
    let mut bytes = [0; 128];
    for (key, value, missing) in [
        (
            1,
            u64::from(NetConfigOp::Clear as u8),
            LinkField::NetVersion,
        ),
        (2, 0, LinkField::Op),
    ] {
        let mut cbor = header().write(1, &mut bytes).unwrap();
        cbor.key(key).unwrap();
        cbor.u64(value).unwrap();
        let len = cbor.finish().unwrap();
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
            Err(LinkError::Missing(missing))
        );
    }
}

/// cites: L-133, P-013
#[test]
fn l_133_unknown_extension_does_not_supply_radio_metadata() {
    let mut bytes = [0; 128];
    let mut cbor = header().write(3, &mut bytes).unwrap();
    cbor.key(1).unwrap();
    cbor.u64(u64::from(NetConfigOp::Clear as u8)).unwrap();
    cbor.key(2).unwrap();
    cbor.u64(0).unwrap();
    cbor.key(99).unwrap();
    cbor.text("extension").unwrap();
    let len = cbor.finish().unwrap();
    assert_eq!(
        NetChange::decode(LinkEnvelope::decode(&bytes[..len]).unwrap()),
        Ok(NetChange::ClearUnwritten)
    );
}
