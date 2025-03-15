#[cfg(test)]
mod tests {
    use crate::ini::Ini;

    #[test]
    fn test_line_continuation() {
        let mut ini = Ini::new();
        let content = "\
[section1]
key1 = value1\
       value2
key2 = this is a \
       very long \
       value

[section2]
key3 = no_continuation
";
        ini.parse_str(content).unwrap();

        assert_eq!(ini.get("section1", "key1"), Some("value1value2"));
        assert_eq!(ini.get("section1", "key2"), Some("this is a very long value"));
        assert_eq!(ini.get("section2", "key3"), Some("no_continuation"));
    }

    #[test]
    fn test_line_continuation_errors() {
        let mut ini = Ini::new();
        
        // Test backslash at end of file
        let content = "[section]\nkey = value\\";
        assert!(ini.parse_str(content).is_err());

        // Test backslash in section header
        let content = "[section\\\n]";
        assert!(ini.parse_str(content).is_err());

        // Test backslash in comment
        let content = "[section]\n# comment\\";
        assert!(ini.parse_str(content).is_ok());
    }
}
