#[cfg(test)]
mod dependency_descriptor_extension_test;

const MAX_TEMPLATES: usize = 64;
const MAX_TEMPORAL_ID: u8 = 7;
const MAX_SPATIAL_ID: u8 = 3;

/// RTP header extension URI for AV1 dependency descriptor.
pub const DEPENDENCY_DESCRIPTOR_URI: &str =
    "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension";

/// Temporal/spatial layer ids derived from dependency descriptor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyDescriptorLayerIds {
    pub temporal_id: u8,
    pub spatial_id: u8,
}

/// A frame's dependency-target indication for one decode target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyDescriptorDecodeTargetIndication {
    NotPresent,
    Discardable,
    Switch,
    Required,
}

impl DependencyDescriptorDecodeTargetIndication {
    fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NotPresent),
            1 => Some(Self::Discardable),
            2 => Some(Self::Switch),
            3 => Some(Self::Required),
            _ => None,
        }
    }
}

/// Verified dependency-descriptor metadata for one RTP packet.
///
/// A value is returned only when the descriptor resolves to an active decode target. Callers can
/// use `first_packet_in_frame` as a descriptor-backed frame boundary; it is not a claim that the
/// frame is an intra/key frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDescriptorPacketMetadata {
    pub frame_number: u16,
    pub layer_ids: DependencyDescriptorLayerIds,
    pub first_packet_in_frame: bool,
    pub last_packet_in_frame: bool,
    /// Effective target activity after this packet, retained until a later descriptor updates it.
    pub active_decode_targets_mask: u32,
    /// One indication per decode-target index for this frame.
    pub decode_target_indications: Vec<DependencyDescriptorDecodeTargetIndication>,
    /// Maximum temporal/spatial layer for each decode-target index in the active structure.
    pub decode_target_layers: Vec<DependencyDescriptorLayerIds>,
    /// Frame-number differences to frames this frame depends on, from the template or custom data.
    pub frame_diffs: Vec<u16>,
    /// Per-chain frame-number differences, from the template or custom data.
    pub chain_diffs: Vec<u8>,
    /// Maps each decode-target index to the chain that protects it. Empty when no chains exist.
    pub decode_target_protected_by_chain: Vec<u8>,
    /// True when an active decode target marks this frame as a switching point.
    pub has_switching_decode_target: bool,
}

const DTI_NOT_PRESENT: u8 = 0;
const DTI_SWITCH: u8 = 2;

#[derive(Debug, Clone)]
struct FrameTemplate {
    layer_ids: DependencyDescriptorLayerIds,
    decode_target_indications: Vec<u8>,
    frame_diffs: Vec<u16>,
    chain_diffs: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct FrameDependencyStructure {
    structure_id: u8,
    num_decode_targets: u8,
    num_chains: u8,
    decode_target_protected_by_chain: Vec<u8>,
    decode_target_layers: Vec<DependencyDescriptorLayerIds>,
    templates: Vec<FrameTemplate>,
}

/// Stateful parser for dependency descriptor RTP header extension payloads.
///
/// The extension can reference a previously sent frame dependency structure.
/// Keep one parser instance per RTP stream/SSRC.
#[derive(Debug, Default, Clone)]
pub struct DependencyDescriptorParser {
    structure: Option<FrameDependencyStructure>,
    active_decode_targets_mask: Option<u32>,
}

impl DependencyDescriptorParser {
    /// Parses one dependency descriptor payload and returns temporal/spatial ids when available.
    ///
    /// Parsing is fail-safe: parser state is updated only when the payload parses successfully.
    pub fn parse_layer_ids(&mut self, payload: &[u8]) -> Option<DependencyDescriptorLayerIds> {
        self.parse_packet_metadata(payload)
            .map(|metadata| metadata.layer_ids)
    }

    /// Parses one descriptor into active-decode-target layer and frame-boundary metadata.
    ///
    /// Parsing is fail-safe: parser state is updated only when the payload parses successfully.
    pub fn parse_packet_metadata(
        &mut self,
        payload: &[u8],
    ) -> Option<DependencyDescriptorPacketMetadata> {
        let mut candidate_structure = self.structure.clone();
        let mut candidate_active_mask = self.active_decode_targets_mask;
        let metadata = parse_packet_metadata_internal(
            payload,
            &mut candidate_structure,
            &mut candidate_active_mask,
        )?;
        self.structure = candidate_structure;
        self.active_decode_targets_mask = candidate_active_mask;
        Some(metadata)
    }
}

/// Replaces or injects the active decode-target mask in a raw dependency-descriptor payload.
///
/// `num_decode_targets` must match the descriptor's dependency structure when it carries one.
/// The replacement mask may set only those decode-target bits. Returns `None` for malformed
/// payloads or invalid mask parameters.
pub fn replace_or_inject_active_decode_target_mask(
    payload: &[u8],
    num_decode_targets: u8,
    replacement_mask: u32,
) -> Option<Vec<u8>> {
    if !(1..=32).contains(&num_decode_targets)
        || replacement_mask & !all_decode_targets_active_mask(num_decode_targets) != 0
    {
        return None;
    }

    const MANDATORY_FIELDS_BITS: usize = 24;
    const ACTIVE_DECODE_TARGETS_PRESENT_BIT: usize = MANDATORY_FIELDS_BITS + 1;

    let mut bits = payload_to_bits(payload);
    if bits.len() < MANDATORY_FIELDS_BITS {
        return None;
    }

    if bits.len() == MANDATORY_FIELDS_BITS {
        bits.extend([false, true, false, false, false]);
        append_mask_bits(&mut bits, replacement_mask, num_decode_targets);
        pad_to_full_byte(&mut bits);
        return Some(bits_to_payload(&bits));
    }

    let mut reader = BitReader::new(payload);
    reader.skip_bits(MANDATORY_FIELDS_BITS)?;
    let template_structure_present = reader.read_bool()?;
    let active_decode_targets_present = reader.read_bool()?;
    let custom_dtis = reader.read_bool()?;
    let custom_fdiffs = reader.read_bool()?;
    let custom_chains = reader.read_bool()?;

    let structure = if template_structure_present {
        let structure = parse_structure(&mut reader)?;
        if structure.num_decode_targets != num_decode_targets {
            return None;
        }
        Some(structure)
    } else {
        None
    };

    let mask_offset = reader.bit_offset;
    let mask_end = mask_offset.checked_add(usize::from(num_decode_targets))?;
    if active_decode_targets_present {
        if mask_end > bits.len() {
            return None;
        }
        write_mask_bits(
            &mut bits[mask_offset..mask_end],
            replacement_mask,
            num_decode_targets,
        );
    } else {
        let payload_end = dependency_descriptor_payload_end(
            payload,
            mask_offset,
            num_decode_targets,
            structure.as_ref().map(|structure| structure.num_chains),
            custom_dtis,
            custom_fdiffs,
            custom_chains,
        );
        if let Some(payload_end) = payload_end {
            bits.truncate(payload_end);
        }
        bits[ACTIVE_DECODE_TARGETS_PRESENT_BIT] = true;
        let mut replacement_bits = Vec::with_capacity(usize::from(num_decode_targets));
        append_mask_bits(&mut replacement_bits, replacement_mask, num_decode_targets);
        bits.splice(mask_offset..mask_offset, replacement_bits);
        pad_to_full_byte(&mut bits);
    }

    Some(bits_to_payload(&bits))
}

fn dependency_descriptor_payload_end(
    payload: &[u8],
    mask_offset: usize,
    num_decode_targets: u8,
    num_chains: Option<u8>,
    custom_dtis: bool,
    custom_fdiffs: bool,
    custom_chains: bool,
) -> Option<usize> {
    let mut reader = BitReader {
        payload,
        bit_offset: mask_offset,
    };
    if custom_dtis {
        reader.skip_bits(usize::from(num_decode_targets) * 2)?;
    }
    if custom_fdiffs {
        parse_custom_frame_diffs(&mut reader)?;
    }
    if custom_chains {
        reader.skip_bits(usize::from(num_chains?) * 8)?;
    }
    Some(reader.bit_offset)
}

fn payload_to_bits(payload: &[u8]) -> Vec<bool> {
    payload
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1 != 0))
        .collect()
}

fn bits_to_payload(bits: &[bool]) -> Vec<u8> {
    let mut payload = vec![0; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            payload[index / 8] |= 1 << (7 - (index % 8));
        }
    }
    payload
}

fn append_mask_bits(bits: &mut Vec<bool>, mask: u32, num_decode_targets: u8) {
    for shift in (0..num_decode_targets).rev() {
        bits.push((mask >> shift) & 1 != 0);
    }
}

fn write_mask_bits(bits: &mut [bool], mask: u32, num_decode_targets: u8) {
    for (bit, shift) in bits.iter_mut().zip((0..num_decode_targets).rev()) {
        *bit = (mask >> shift) & 1 != 0;
    }
}

fn pad_to_full_byte(bits: &mut Vec<bool>) {
    bits.resize(bits.len().next_multiple_of(8), false);
}

fn parse_packet_metadata_internal(
    payload: &[u8],
    structure: &mut Option<FrameDependencyStructure>,
    active_decode_targets_mask_state: &mut Option<u32>,
) -> Option<DependencyDescriptorPacketMetadata> {
    let mut reader = BitReader::new(payload);

    // mandatory fields
    let first_packet_in_frame = reader.read_bool()?;
    let last_packet_in_frame = reader.read_bool()?;
    let frame_dependency_template_id = reader.read_bits_u8(6)?;
    let frame_number = u16::try_from(reader.read_bits(16)?).ok()?;

    let mut active_decode_targets_present = false;
    let mut custom_dtis = false;
    let mut custom_fdiffs = false;
    let mut custom_chains = false;
    let mut active_decode_targets_mask: Option<u32> = None;

    // extended fields are present only when there are extra bits available.
    if reader.bits_remaining() > 0 {
        let template_structure_present = reader.read_bool()?;
        active_decode_targets_present = reader.read_bool()?;
        custom_dtis = reader.read_bool()?;
        custom_fdiffs = reader.read_bool()?;
        custom_chains = reader.read_bool()?;

        if template_structure_present {
            let parsed = parse_structure(&mut reader)?;
            active_decode_targets_mask =
                Some(all_decode_targets_active_mask(parsed.num_decode_targets));
            *structure = Some(parsed);
        }
    }

    let structure_ref = structure.as_ref()?;

    if active_decode_targets_present {
        let mask_bits = reader.read_bits(usize::from(structure_ref.num_decode_targets))? as u32;
        active_decode_targets_mask = Some(mask_bits);
    }

    let template_index = (usize::from(frame_dependency_template_id) + MAX_TEMPLATES
        - usize::from(structure_ref.structure_id))
        % MAX_TEMPLATES;
    let template = structure_ref.templates.get(template_index)?;
    let layer_ids = template.layer_ids;

    let decode_target_indications = if custom_dtis {
        let mut frame_dtis = Vec::with_capacity(usize::from(structure_ref.num_decode_targets));
        for _ in 0..structure_ref.num_decode_targets {
            frame_dtis.push(reader.read_bits_u8(2)?);
        }
        frame_dtis
    } else {
        template.decode_target_indications.clone()
    };

    let frame_diffs = if custom_fdiffs {
        parse_custom_frame_diffs(&mut reader)?
    } else {
        template.frame_diffs.clone()
    };

    let chain_diffs = if custom_chains {
        let mut chain_diffs = Vec::with_capacity(usize::from(structure_ref.num_chains));
        for _ in 0..structure_ref.num_chains {
            chain_diffs.push(reader.read_bits_u8(8)?);
        }
        chain_diffs
    } else {
        template.chain_diffs.clone()
    };

    if layer_ids.temporal_id > MAX_TEMPORAL_ID || layer_ids.spatial_id > MAX_SPATIAL_ID {
        return None;
    }

    let active_decode_targets_mask = active_decode_targets_mask
        .or(*active_decode_targets_mask_state)
        .unwrap_or_else(|| all_decode_targets_active_mask(structure_ref.num_decode_targets));
    *active_decode_targets_mask_state = Some(active_decode_targets_mask);
    if !has_any_active_decode_target(&decode_target_indications, active_decode_targets_mask) {
        return None;
    }

    let has_switching_decode_target =
        has_switching_decode_target(&decode_target_indications, active_decode_targets_mask);
    let decode_target_indications = decode_target_indications
        .into_iter()
        .map(DependencyDescriptorDecodeTargetIndication::from_wire)
        .collect::<Option<Vec<_>>>()?;
    Some(DependencyDescriptorPacketMetadata {
        frame_number,
        layer_ids,
        first_packet_in_frame,
        last_packet_in_frame,
        active_decode_targets_mask,
        decode_target_indications,
        decode_target_layers: structure_ref.decode_target_layers.clone(),
        frame_diffs,
        chain_diffs,
        decode_target_protected_by_chain: structure_ref.decode_target_protected_by_chain.clone(),
        has_switching_decode_target,
    })
}

fn parse_structure(reader: &mut BitReader<'_>) -> Option<FrameDependencyStructure> {
    let structure_id = reader.read_bits_u8(6)?;
    let num_decode_targets = reader.read_bits_u8(5)?.checked_add(1)?;

    let mut template_layer_ids = Vec::new();
    let mut temporal_id: u8 = 0;
    let mut spatial_id: u8 = 0;

    loop {
        template_layer_ids.push(DependencyDescriptorLayerIds {
            temporal_id,
            spatial_id,
        });

        let next_layer_idc = reader.read_bits_u8(2)?;
        match next_layer_idc {
            0 => {}
            1 => {
                temporal_id = temporal_id.checked_add(1)?;
                if temporal_id > MAX_TEMPORAL_ID {
                    return None;
                }
            }
            2 => {
                spatial_id = spatial_id.checked_add(1)?;
                temporal_id = 0;
                if spatial_id > MAX_SPATIAL_ID {
                    return None;
                }
            }
            3 => break,
            _ => return None,
        }

        if template_layer_ids.len() >= MAX_TEMPLATES {
            return None;
        }
    }

    // template dtis
    let mut templates = Vec::with_capacity(template_layer_ids.len());
    for layer_ids in template_layer_ids {
        let mut decode_target_indications = Vec::with_capacity(usize::from(num_decode_targets));
        for _ in 0..num_decode_targets {
            decode_target_indications.push(reader.read_bits_u8(2)?);
        }
        templates.push(FrameTemplate {
            layer_ids,
            decode_target_indications,
            frame_diffs: Vec::new(),
            chain_diffs: Vec::new(),
        });
    }

    // template fdiffs: each template has repeated [follow_bit, 4-bit diff] entries until follow=false
    for template in &mut templates {
        loop {
            let follow = reader.read_bool()?;
            if !follow {
                break;
            }
            template
                .frame_diffs
                .push(u16::from(reader.read_bits_u8(4)?) + 1);
        }
    }

    // template chains
    let num_chains = read_non_symmetric(reader, u32::from(num_decode_targets) + 1)? as u8;
    let mut decode_target_protected_by_chain = Vec::new();
    if num_chains > 0 {
        decode_target_protected_by_chain.reserve(usize::from(num_decode_targets));
        for _ in 0..num_decode_targets {
            decode_target_protected_by_chain
                .push(u8::try_from(read_non_symmetric(reader, u32::from(num_chains))?).ok()?);
        }
        for template in &mut templates {
            template.chain_diffs.reserve(usize::from(num_chains));
            for _ in 0..num_chains {
                template.chain_diffs.push(reader.read_bits_u8(4)?);
            }
        }
    }

    let decode_target_layers = (0..num_decode_targets)
        .map(|target| {
            templates
                .iter()
                .filter(|template| {
                    template.decode_target_indications[usize::from(target)] != DTI_NOT_PRESENT
                })
                .fold(
                    DependencyDescriptorLayerIds {
                        temporal_id: 0,
                        spatial_id: 0,
                    },
                    |layer, template| DependencyDescriptorLayerIds {
                        temporal_id: layer.temporal_id.max(template.layer_ids.temporal_id),
                        spatial_id: layer.spatial_id.max(template.layer_ids.spatial_id),
                    },
                )
        })
        .collect();

    // optional resolutions
    if reader.read_bool()? {
        let max_spatial = templates
            .iter()
            .map(|t| t.layer_ids.spatial_id)
            .max()
            .unwrap_or(0);
        for _ in 0..=max_spatial {
            reader.skip_bits(16)?;
            reader.skip_bits(16)?;
        }
    }

    Some(FrameDependencyStructure {
        structure_id,
        num_decode_targets,
        num_chains,
        decode_target_protected_by_chain,
        decode_target_layers,
        templates,
    })
}

fn parse_custom_frame_diffs(reader: &mut BitReader<'_>) -> Option<Vec<u16>> {
    let mut frame_diffs = Vec::new();
    loop {
        let next_fdiff_size = reader.read_bits(2)? as usize;
        if next_fdiff_size == 0 {
            return Some(frame_diffs);
        }
        let frame_diff_minus_one = reader.read_bits(next_fdiff_size * 4)?;
        frame_diffs.push(u16::try_from(frame_diff_minus_one.checked_add(1)?).ok()?);
    }
}

fn read_non_symmetric(reader: &mut BitReader<'_>, num_values: u32) -> Option<u32> {
    if num_values == 0 || num_values >= (1u32 << 31) {
        return None;
    }
    if num_values == 1 {
        return Some(0);
    }

    let width = bit_width(num_values);
    let num_min_bits_values = (1u32 << width) - num_values;

    let val = reader.read_bits((width - 1) as usize)? as u32;
    if val < num_min_bits_values {
        return Some(val);
    }

    let bit = reader.read_bits(1)? as u32;
    Some(
        (val << 1)
            .checked_add(bit)?
            .checked_sub(num_min_bits_values)?,
    )
}

fn all_decode_targets_active_mask(num_decode_targets: u8) -> u32 {
    if num_decode_targets >= 32 {
        u32::MAX
    } else {
        (1u32 << num_decode_targets) - 1
    }
}

fn has_any_active_decode_target(decode_target_indications: &[u8], active_mask: u32) -> bool {
    decode_target_indications
        .iter()
        .enumerate()
        .any(|(index, dti)| (active_mask & (1u32 << index)) != 0 && *dti != DTI_NOT_PRESENT)
}

fn has_switching_decode_target(decode_target_indications: &[u8], active_mask: u32) -> bool {
    decode_target_indications
        .iter()
        .enumerate()
        .any(|(index, dti)| (active_mask & (1u32 << index)) != 0 && *dti == DTI_SWITCH)
}

fn bit_width(mut n: u32) -> u32 {
    let mut width = 0;
    while n != 0 {
        n >>= 1;
        width += 1;
    }
    width
}

#[derive(Debug, Clone, Copy)]
struct BitReader<'a> {
    payload: &'a [u8],
    bit_offset: usize,
}

impl<'a> BitReader<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            bit_offset: 0,
        }
    }

    fn bits_remaining(&self) -> usize {
        self.payload
            .len()
            .saturating_mul(8)
            .saturating_sub(self.bit_offset)
    }

    fn read_bool(&mut self) -> Option<bool> {
        Some(self.read_bits(1)? != 0)
    }

    fn read_bits_u8(&mut self, bits: usize) -> Option<u8> {
        let value = self.read_bits(bits)?;
        u8::try_from(value).ok()
    }

    fn skip_bits(&mut self, bits: usize) -> Option<()> {
        if bits > self.bits_remaining() {
            return None;
        }
        self.bit_offset += bits;
        Some(())
    }

    fn read_bits(&mut self, bits: usize) -> Option<u64> {
        if bits == 0 || bits > 56 || bits > self.bits_remaining() {
            return None;
        }

        let mut value: u64 = 0;
        for _ in 0..bits {
            let byte_index = self.bit_offset / 8;
            let bit_in_byte = 7 - (self.bit_offset % 8);
            let bit = (self.payload.get(byte_index)? >> bit_in_byte) & 1;
            value = (value << 1) | u64::from(bit);
            self.bit_offset += 1;
        }

        Some(value)
    }
}
