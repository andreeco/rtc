use super::*;

#[derive(Default)]
struct BitWriter {
    bits: Vec<bool>,
}

impl BitWriter {
    fn push(&mut self, value: u64, width: usize) {
        for i in (0..width).rev() {
            self.bits.push(((value >> i) & 1) == 1);
        }
    }

    fn push_bool(&mut self, value: bool) {
        self.bits.push(value);
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut out = vec![0u8; self.bits.len().div_ceil(8)];
        for (i, bit) in self.bits.iter().enumerate() {
            if *bit {
                let byte_index = i / 8;
                let bit_index = 7 - (i % 8);
                out[byte_index] |= 1 << bit_index;
            }
        }
        out
    }
}

fn build_dd_payload(
    template_id: u8,
    frame_number: u16,
    include_structure: bool,
    templates_next_layer_idc: &[u8],
) -> Vec<u8> {
    let mut w = BitWriter::default();

    // mandatory fields
    w.push_bool(true); // first packet in frame
    w.push_bool(true); // last packet in frame
    w.push(u64::from(template_id), 6);
    w.push(u64::from(frame_number), 16);

    if include_structure {
        // extended field flags
        w.push_bool(true); // template dependency structure present
        w.push_bool(false); // active decode targets present
        w.push_bool(false); // custom dtis
        w.push_bool(false); // custom fdiffs
        w.push_bool(false); // custom chains

        // structure
        w.push(0, 6); // structure_id
        w.push(0, 5); // num_decode_targets-1 => 1 target

        // template layer transitions
        for idc in templates_next_layer_idc {
            w.push(u64::from(*idc), 2);
        }

        let template_count = templates_next_layer_idc.len();

        // template dtis: one decode target per template
        for _ in 0..template_count {
            w.push(3, 2); // required
        }

        // template fdiffs: none
        for _ in 0..template_count {
            w.push_bool(false);
        }

        // num chains in non-symmetric [0..num_decode_targets] => num_values=2
        // encoding 0 as one bit 0.
        w.push_bool(false);

        // no resolutions
        w.push_bool(false);
    }

    w.into_bytes()
}

#[test]
fn dependency_descriptor_parser_reads_template_temporal_layer() {
    let mut parser = DependencyDescriptorParser::default();

    // Two templates: (0,0) then nextTemporal => (1,0), then stop.
    let payload = build_dd_payload(1, 1, true, &[1, 3]);

    assert_eq!(
        parser.parse_layer_ids(&payload),
        Some(DependencyDescriptorLayerIds {
            temporal_id: 1,
            spatial_id: 0,
        })
    );
}

#[test]
fn dependency_descriptor_parser_reads_template_spatial_layer() {
    let mut parser = DependencyDescriptorParser::default();

    // Two templates: (0,0) then nextSpatial => (0,1), then stop.
    let payload = build_dd_payload(1, 1, true, &[2, 3]);

    assert_eq!(
        parser.parse_layer_ids(&payload),
        Some(DependencyDescriptorLayerIds {
            temporal_id: 0,
            spatial_id: 1,
        })
    );
}

#[test]
fn dependency_descriptor_parser_uses_cached_structure_on_followup_packets() {
    let mut parser = DependencyDescriptorParser::default();

    // Prime parser with structure defining two templates.
    let with_structure = build_dd_payload(1, 1, true, &[1, 3]);
    assert!(parser.parse_layer_ids(&with_structure).is_some());

    // Follow-up packet carries only mandatory fields, selecting template 0.
    let follow_up = build_dd_payload(0, 2, false, &[]);

    assert_eq!(
        parser.parse_layer_ids(&follow_up),
        Some(DependencyDescriptorLayerIds {
            temporal_id: 0,
            spatial_id: 0,
        })
    );
}

#[test]
fn dependency_descriptor_parser_rejects_payload_without_structure_context() {
    let mut parser = DependencyDescriptorParser::default();
    let payload = build_dd_payload(0, 1, false, &[]);
    assert_eq!(parser.parse_layer_ids(&payload), None);
}
