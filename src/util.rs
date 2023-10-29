// DKIM Milter – milter for DKIM signing and verification
// Copyright © 2022–2023 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

/// Replaces LF and CRLF line breaks uniformly with CRLF.
pub fn normalize_to_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());

    let mut iter = bytes.split(|&b| b == b'\n').peekable();

    while let Some(slice) = iter.next() {
        if iter.peek().is_some() {
            let slice = slice.strip_suffix(b"\r").unwrap_or(slice);
            result.extend(slice);
            result.extend(b"\r\n");
        } else {
            result.extend(slice);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_to_crlf_ok() {
        assert_eq!(normalize_to_crlf(b""), b"");
        assert_eq!(normalize_to_crlf(b"a"), b"a");
        assert_eq!(normalize_to_crlf(b"\r"), b"\r");
        assert_eq!(normalize_to_crlf(b"\n"), b"\r\n");
        assert_eq!(normalize_to_crlf(b"\r\n"), b"\r\n");

        assert_eq!(
            normalize_to_crlf(b"a\r\nb\n\rc\r\n\nde"),
            b"a\r\nb\r\n\rc\r\n\r\nde"
        );
    }
}
