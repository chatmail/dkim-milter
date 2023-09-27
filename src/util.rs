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
