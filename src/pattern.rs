use crate::Error;

/// Byte pattern with `??` wildcards, e.g. `"48 8D 15 ?? ?? ?? ??"`
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    pub fn new(pattern: &'static str) -> Result<Pattern, Error> {
        let bytes = pattern
            .split_whitespace()
            .map(|byte| match byte {
                "??" => Ok(None),
                byte => u8::from_str_radix(byte, 16).map(Some),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidPattern(pattern))?;
        if bytes.is_empty() {
            return Err(Error::InvalidPattern(pattern));
        }
        Ok(Pattern { bytes })
    }

    pub fn find(&self, haystack: &[u8]) -> Option<usize> {
        self.find_all(haystack).next()
    }

    pub fn find_all<'a>(&'a self, haystack: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        haystack
            .windows(self.bytes.len())
            .enumerate()
            .filter(|(_, window)| {
                window
                    .iter()
                    .zip(&self.bytes)
                    .all(|(byte, expected)| expected.is_none_or(|expected| *byte == expected))
            })
            .map(|(offset, _)| offset)
    }

    pub fn find_unique(&self, haystack: &[u8]) -> Option<usize> {
        let offset = self.find(haystack)?;
        match self.find(&haystack[offset + 1..]) {
            Some(_) => None,
            None => Some(offset),
        }
    }
}

/// Resolves the target of a `rel32` operand located at `address`
pub unsafe fn rel32(address: usize) -> usize {
    let displacement = unsafe { std::ptr::read_unaligned(address as *const i32) };
    (address + 4).wrapping_add_signed(displacement as isize)
}

const IMAGE_SCN_MEM_EXECUTE: usize = 0x20000000;

/// Protected binaries rename their sections, so the code is not necessarily in `.text`
pub unsafe fn code_sections(image_base: usize) -> Vec<&'static [u8]> {
    unsafe {
        let read_u16 = |address: usize| std::ptr::read_unaligned(address as *const u16) as usize;
        let read_u32 = |address: usize| std::ptr::read_unaligned(address as *const u32) as usize;

        let nt_headers = image_base + read_u32(image_base + 0x3c);
        let number_of_sections = read_u16(nt_headers + 0x6);
        let size_of_optional_header = read_u16(nt_headers + 0x14);
        let sections = nt_headers + 0x18 + size_of_optional_header;

        (0..number_of_sections)
            .map(|index| sections + index * 0x28)
            .filter(|section| read_u32(section + 0x24) & IMAGE_SCN_MEM_EXECUTE != 0)
            .map(|section| {
                let virtual_size = read_u32(section + 0x8);
                let virtual_address = read_u32(section + 0xc);
                std::slice::from_raw_parts(
                    (image_base + virtual_address) as *const u8,
                    virtual_size,
                )
            })
            .collect()
    }
}
