pub fn enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn dec(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip_and_refusals() {
        assert_eq!(super::dec(&super::enc(&[0, 255, 16])), Some(vec![0, 255, 16]));
        assert_eq!(super::dec("abc"), None);
        assert_eq!(super::dec("zz"), None);
    }
}
