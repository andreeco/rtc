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

#[derive(Debug, Clone, Default)]
struct FrameDependencyStructure {
    structure_id: u8,
    num_decode_targets: u8,
    num_chains: u8,
    templates: Vec<DependencyDescriptorLayerIds>,
}

/// Stateful parser for dependency descriptor RTP header extension payloads.
///
/// The extension can reference a previously sent frame dependency structure.
/// Keep one parser instance per RTP stream/SSRC.
#[derive(Debug, Default, Clone)]
pub struct DependencyDescriptorParser {
    structure: Option<FrameDependencyStructure>,
}

impl DependencyDescriptorParser {
    /// Parses one dependency descriptor payload and returns temporal/spatial ids when available.
    ///
    /// Parsing is fail-safe: parser state is updated only when the payload parses successfully.
    pub fn parse_layer_ids(&mut self, payload: &[u8]) -> Option<DependencyDescriptorLayerIds> {
        let mut candidate_structure = self.structure.clone();
        let ids = parse_layer_ids_internal(payload, &mut candidate_structure)?;
        self.structure = candidate_structure;
        Some(ids)
    }
}

fn parse_layer_ids_internal(
    payload: &[u8],
    structure: &mut Option<FrameDependencyStructure>,
) -> Option<DependencyDescriptorLayerIds> {
    let mut reader = BitReader::new(payload);

    // mandatory fields
    let _first_packet_in_frame = reader.read_bool()?;
    let _last_packet_in_frame = reader.read_bool()?;
    let frame_dependency_template_id = reader.read_bits_u8(6)?;
    let _frame_number = reader.read_bits(16)?;

    let mut active_decode_targets_present = false;
    let mut custom_dtis = false;
    let mut custom_fdiffs = false;
    let mut custom_chains = false;

    // extended fields are present only when there are extra bits available.
    if reader.bits_remaining() > 0 {
        let template_structure_present = reader.read_bool()?;
        active_decode_targets_present = reader.read_bool()?;
        custom_dtis = reader.read_bool()?;
        custom_fdiffs = reader.read_bool()?;
        custom_chains = reader.read_bool()?;

        if template_structure_present {
            *structure = Some(parse_structure(&mut reader)?);
        }
    }

    let structure_ref = structure.as_ref()?;

    if active_decode_targets_present {
        reader.skip_bits(usize::from(structure_ref.num_decode_targets))?;
    }

    let template_index = (usize::from(frame_dependency_template_id) + MAX_TEMPLATES
        - usize::from(structure_ref.structure_id))
        % MAX_TEMPLATES;
    let layer_ids = *structure_ref.templates.get(template_index)?;

    if custom_dtis {
        reader.skip_bits(usize::from(structure_ref.num_decode_targets) * 2)?;
    }

    if custom_fdiffs {
        loop {
            let next_fdiff_size = reader.read_bits(2)?;
            if next_fdiff_size == 0 {
                break;
            }
            reader.skip_bits(next_fdiff_size as usize * 4)?;
        }
    }

    if custom_chains {
        reader.skip_bits(usize::from(structure_ref.num_chains) * 8)?;
    }

    if layer_ids.temporal_id > MAX_TEMPORAL_ID || layer_ids.spatial_id > MAX_SPATIAL_ID {
        return None;
    }

    Some(layer_ids)
}

fn parse_structure(reader: &mut BitReader<'_>) -> Option<FrameDependencyStructure> {
    let structure_id = reader.read_bits_u8(6)?;
    let num_decode_targets = reader.read_bits_u8(5)?.checked_add(1)?;

    let mut templates = Vec::new();
    let mut temporal_id: u8 = 0;
    let mut spatial_id: u8 = 0;

    loop {
        templates.push(DependencyDescriptorLayerIds {
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

        if templates.len() >= MAX_TEMPLATES {
            return None;
        }
    }

    // template dtis
    reader.skip_bits(templates.len() * usize::from(num_decode_targets) * 2)?;

    // template fdiffs: each template has repeated [follow_bit, 4-bit diff] entries until follow=false
    for _ in 0..templates.len() {
        loop {
            let follow = reader.read_bool()?;
            if !follow {
                break;
            }
            reader.skip_bits(4)?;
        }
    }

    // template chains
    let num_chains = read_non_symmetric(reader, u32::from(num_decode_targets) + 1)? as u8;
    if num_chains > 0 {
        for _ in 0..num_decode_targets {
            read_non_symmetric(reader, u32::from(num_chains))?;
        }
        reader.skip_bits(templates.len() * usize::from(num_chains) * 4)?;
    }

    // optional resolutions
    if reader.read_bool()? {
        let max_spatial = templates.iter().map(|t| t.spatial_id).max().unwrap_or(0);
        for _ in 0..=max_spatial {
            reader.skip_bits(16)?;
            reader.skip_bits(16)?;
        }
    }

    Some(FrameDependencyStructure {
        structure_id,
        num_decode_targets,
        num_chains,
        templates,
    })
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
