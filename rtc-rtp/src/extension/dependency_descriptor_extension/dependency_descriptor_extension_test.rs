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

#[derive(Default, Clone, Copy)]
struct DdPayloadOptions {
    active_decode_targets_mask: Option<u8>,
    custom_dti: Option<u8>,
}

fn build_dd_payload_with_options(
    template_id: u8,
    frame_number: u16,
    include_structure: bool,
    templates_next_layer_idc: &[u8],
    options: DdPayloadOptions,
) -> Vec<u8> {
    let mut w = BitWriter::default();

    // mandatory fields
    w.push_bool(true); // first packet in frame
    w.push_bool(true); // last packet in frame
    w.push(u64::from(template_id), 6);
    w.push(u64::from(frame_number), 16);

    if include_structure
        || options.active_decode_targets_mask.is_some()
        || options.custom_dti.is_some()
    {
        // extended field flags
        w.push_bool(include_structure); // template dependency structure present
        w.push_bool(options.active_decode_targets_mask.is_some()); // active decode targets present
        w.push_bool(options.custom_dti.is_some()); // custom dtis
        w.push_bool(false); // custom fdiffs
        w.push_bool(false); // custom chains

        if include_structure {
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

        if let Some(mask) = options.active_decode_targets_mask {
            w.push(u64::from(mask), 1); // one decode target in these fixtures
        }

        if let Some(custom_dti) = options.custom_dti {
            w.push(u64::from(custom_dti), 2); // one decode target in these fixtures
        }
    }

    w.into_bytes()
}

fn build_dd_payload(
    template_id: u8,
    frame_number: u16,
    include_structure: bool,
    templates_next_layer_idc: &[u8],
) -> Vec<u8> {
    build_dd_payload_with_options(
        template_id,
        frame_number,
        include_structure,
        templates_next_layer_idc,
        DdPayloadOptions::default(),
    )
}

fn build_multi_target_descriptor(
    template_id: u8,
    frame_number: u16,
    include_structure: bool,
    active_decode_targets_mask: Option<u8>,
    custom_dtis: Option<[u8; 3]>,
    custom_frame_diffs: Option<&[u16]>,
    custom_chain_diffs: Option<[u8; 2]>,
) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.push_bool(true);
    w.push_bool(true);
    w.push(u64::from(template_id), 6);
    w.push(u64::from(frame_number), 16);

    let has_extended_fields = include_structure
        || active_decode_targets_mask.is_some()
        || custom_dtis.is_some()
        || custom_frame_diffs.is_some()
        || custom_chain_diffs.is_some();
    if !has_extended_fields {
        return w.into_bytes();
    }

    w.push_bool(include_structure);
    w.push_bool(active_decode_targets_mask.is_some());
    w.push_bool(custom_dtis.is_some());
    w.push_bool(custom_frame_diffs.is_some());
    w.push_bool(custom_chain_diffs.is_some());

    if include_structure {
        w.push(0, 6); // structure id
        w.push(2, 5); // three decode targets
        w.push(1, 2); // template 0 -> next temporal layer
        w.push(3, 2); // template 1 -> no more templates

        // Template DTIs: [R, -, S], then [D, R, R].
        for dti in [3, 0, 2, 1, 3, 3] {
            w.push(dti, 2);
        }

        // Template frame diffs: [1, 4], then [2].
        for diff in [1, 4] {
            w.push_bool(true);
            w.push(diff - 1, 4);
        }
        w.push_bool(false);
        w.push_bool(true);
        w.push(1, 4);
        w.push_bool(false);

        w.push(2, 2); // two chains, encoded non-symmetrically in [0, 4).
        for protected_by_chain in [0, 1, 0] {
            w.push(protected_by_chain, 1);
        }
        for chain_diff in [3, 5, 7, 9] {
            w.push(chain_diff, 4);
        }
        w.push_bool(false); // no resolutions
    }

    if let Some(mask) = active_decode_targets_mask {
        w.push(u64::from(mask), 3);
    }
    if let Some(dtis) = custom_dtis {
        for dti in dtis {
            w.push(u64::from(dti), 2);
        }
    }
    if let Some(frame_diffs) = custom_frame_diffs {
        for &frame_diff in frame_diffs {
            let (size, width) = if frame_diff <= 16 {
                (1, 4)
            } else if frame_diff <= 256 {
                (2, 8)
            } else {
                (3, 12)
            };
            w.push(size, 2);
            w.push(u64::from(frame_diff - 1), width);
        }
        w.push(0, 2);
    }
    if let Some(chain_diffs) = custom_chain_diffs {
        for chain_diff in chain_diffs {
            w.push(u64::from(chain_diff), 8);
        }
    }

    w.into_bytes()
}

#[test]
fn dependency_descriptor_parser_retains_multi_target_selector_state_and_overrides() {
    let mut parser = DependencyDescriptorParser::default();

    let template_packet = build_multi_target_descriptor(1, 1, true, None, None, None, None);
    let template_metadata = parser
        .parse_packet_metadata(&template_packet)
        .expect("template descriptor should parse");
    assert_eq!(template_metadata.active_decode_targets_mask, 0b111);
    assert_eq!(
        template_metadata.decode_target_layers,
        vec![
            DependencyDescriptorLayerIds {
                temporal_id: 1,
                spatial_id: 0,
            },
            DependencyDescriptorLayerIds {
                temporal_id: 1,
                spatial_id: 0,
            },
            DependencyDescriptorLayerIds {
                temporal_id: 1,
                spatial_id: 0,
            },
        ]
    );
    assert_eq!(template_metadata.frame_diffs, vec![2]);
    assert_eq!(template_metadata.chain_diffs, vec![7, 9]);
    assert_eq!(
        template_metadata.decode_target_protected_by_chain,
        vec![0, 1, 0]
    );

    let override_packet = build_multi_target_descriptor(
        1,
        2,
        false,
        Some(0b110),
        Some([0, 2, 3]),
        Some(&[1, 300]),
        Some([11, 0]),
    );
    let override_metadata = parser
        .parse_packet_metadata(&override_packet)
        .expect("custom descriptor should parse");
    assert_eq!(override_metadata.active_decode_targets_mask, 0b110);
    assert_eq!(
        override_metadata.decode_target_indications,
        vec![
            DependencyDescriptorDecodeTargetIndication::NotPresent,
            DependencyDescriptorDecodeTargetIndication::Switch,
            DependencyDescriptorDecodeTargetIndication::Required,
        ]
    );
    assert!(override_metadata.has_switching_decode_target);
    assert_eq!(override_metadata.frame_diffs, vec![1, 300]);
    assert_eq!(override_metadata.chain_diffs, vec![11, 0]);
    assert_eq!(
        override_metadata.decode_target_protected_by_chain,
        vec![0, 1, 0]
    );
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
fn dependency_descriptor_parser_reports_verified_frame_start_metadata() {
    let mut parser = DependencyDescriptorParser::default();
    let payload = build_dd_payload(1, 1, true, &[1, 3]);

    assert_eq!(
        parser.parse_packet_metadata(&payload),
        Some(DependencyDescriptorPacketMetadata {
            frame_number: 1,
            layer_ids: DependencyDescriptorLayerIds {
                temporal_id: 1,
                spatial_id: 0,
            },
            first_packet_in_frame: true,
            last_packet_in_frame: true,
            active_decode_targets_mask: 1,
            decode_target_indications: vec![DependencyDescriptorDecodeTargetIndication::Required],
            decode_target_layers: vec![DependencyDescriptorLayerIds {
                temporal_id: 1,
                spatial_id: 0,
            }],
            frame_diffs: vec![],
            chain_diffs: vec![],
            decode_target_protected_by_chain: vec![],
            has_switching_decode_target: false,
        })
    );
}

#[test]
fn dependency_descriptor_parser_preserves_non_first_frame_boundary_metadata() {
    let mut parser = DependencyDescriptorParser::default();
    let with_structure = build_dd_payload(0, 1, true, &[3]);
    assert!(parser.parse_packet_metadata(&with_structure).is_some());

    let mut follow_up = build_dd_payload(0, 2, false, &[]);
    follow_up[0] &= 0x7f; // first_packet_in_frame = false
    assert_eq!(
        parser.parse_packet_metadata(&follow_up),
        Some(DependencyDescriptorPacketMetadata {
            frame_number: 2,
            layer_ids: DependencyDescriptorLayerIds {
                temporal_id: 0,
                spatial_id: 0,
            },
            first_packet_in_frame: false,
            last_packet_in_frame: true,
            active_decode_targets_mask: 1,
            decode_target_indications: vec![DependencyDescriptorDecodeTargetIndication::Required],
            decode_target_layers: vec![DependencyDescriptorLayerIds {
                temporal_id: 0,
                spatial_id: 0,
            }],
            frame_diffs: vec![],
            chain_diffs: vec![],
            decode_target_protected_by_chain: vec![],
            has_switching_decode_target: false,
        })
    );
}

#[test]
fn dependency_descriptor_parser_reports_active_switch_decode_target() {
    let mut parser = DependencyDescriptorParser::default();
    let with_structure = build_dd_payload(0, 1, true, &[3]);
    assert!(parser.parse_packet_metadata(&with_structure).is_some());
    let switch = build_dd_payload_with_options(
        0,
        2,
        false,
        &[],
        DdPayloadOptions {
            active_decode_targets_mask: Some(1),
            custom_dti: Some(2),
        },
    );
    assert!(
        parser
            .parse_packet_metadata(&switch)
            .is_some_and(
                |metadata| metadata.first_packet_in_frame && metadata.has_switching_decode_target
            )
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

#[test]
fn dependency_descriptor_parser_respects_active_decode_target_mask() {
    let mut parser = DependencyDescriptorParser::default();

    let payload = build_dd_payload_with_options(
        0,
        1,
        true,
        &[3],
        DdPayloadOptions {
            active_decode_targets_mask: Some(0),
            custom_dti: None,
        },
    );

    assert_eq!(parser.parse_layer_ids(&payload), None);
}

#[test]
fn dependency_descriptor_parser_respects_custom_dti_presence() {
    let mut parser = DependencyDescriptorParser::default();

    // Prime structure context with one template and one decode target.
    let with_structure = build_dd_payload(0, 1, true, &[3]);
    assert!(parser.parse_layer_ids(&with_structure).is_some());

    let custom_not_present = build_dd_payload_with_options(
        0,
        2,
        false,
        &[],
        DdPayloadOptions {
            active_decode_targets_mask: Some(1),
            custom_dti: Some(0),
        },
    );
    assert_eq!(parser.parse_layer_ids(&custom_not_present), None);

    let custom_required = build_dd_payload_with_options(
        0,
        3,
        false,
        &[],
        DdPayloadOptions {
            active_decode_targets_mask: Some(1),
            custom_dti: Some(3),
        },
    );
    assert_eq!(
        parser.parse_layer_ids(&custom_required),
        Some(DependencyDescriptorLayerIds {
            temporal_id: 0,
            spatial_id: 0,
        })
    );
}
