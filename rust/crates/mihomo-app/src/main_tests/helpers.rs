    fn parse_ech_public_name(config_base64: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(config_base64)
            .unwrap();
        let mut cursor = 0_usize;
        let list_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(bytes.len() - cursor, list_len);
        let extension = read_u16(&bytes, &mut cursor);
        assert_eq!(extension, 0xfe0d);
        let config_len = read_u16(&bytes, &mut cursor) as usize;
        let config_end = cursor + config_len;
        let id = bytes[cursor];
        cursor += 1;
        assert_eq!(id, 0);
        assert_eq!(read_u16(&bytes, &mut cursor), 0x0020);
        let pub_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(pub_len, 32);
        cursor += pub_len;
        let suites_len = read_u16(&bytes, &mut cursor) as usize;
        assert_eq!(suites_len, 12);
        cursor += suites_len;
        let max_name_len = bytes[cursor];
        cursor += 1;
        assert_eq!(max_name_len, 0);
        let name_len = bytes[cursor] as usize;
        cursor += 1;
        let public_name = String::from_utf8(bytes[cursor..cursor + name_len].to_vec()).unwrap();
        cursor += name_len;
        assert_eq!(read_u16(&bytes, &mut cursor), 0);
        assert_eq!(cursor, config_end);
        public_name
    }

    fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
        let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
        *cursor += 2;
        value
    }

    #[cfg(unix)]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn unique_temp_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mihomo-app-main-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
