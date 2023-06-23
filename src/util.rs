pub fn convert_strings_to_strs(strings: &Vec<String>) -> Vec<&str> {
    strings.iter().map(|s| s.as_str()).collect()
}
