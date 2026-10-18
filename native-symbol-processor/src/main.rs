//! File-only symbolication. No source server, debug companion or network resolution.
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{self, Write},
};
use symbolic_common::DebugId;
use symbolic_debuginfo::{Archive, FileFormat};
use symbolic_demangle::{Demangle, DemangleOptions};
use symbolic_symcache::{SymCache, SymCacheConverter};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    format: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    expected: Option<Expected>,
    addresses: Vec<String>,
}

fn strict_debug_id(raw: &str) -> Option<DebugId> {
    // The upstream parser permits trailing appendix text; identity matching must not.
    if !raw.is_ascii() {
        return None;
    }
    let hyphenated = raw.as_bytes().get(8) == Some(&b'-');
    let uuid_length = if hyphenated { 36 } else { 32 };
    let uuid = raw.get(..uuid_length)?;
    if !uuid.bytes().enumerate().all(|(index, byte)| {
        if hyphenated && [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    }) {
        return None;
    }
    let tail = &raw[uuid_length..];
    if !tail.is_empty() {
        let age = if hyphenated {
            tail.strip_prefix('-')?
        } else {
            tail
        };
        if age.is_empty() || age.len() > 8 || !age.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
    }
    raw.parse().ok()
}

fn identity_matches(expected: &Expected, identity: &Value) -> bool {
    let parsed = strict_debug_id(&expected.debug_id);
    let actual = strict_debug_id(identity["debug_id"].as_str().unwrap_or(""));
    expected.format == identity["format"]
        && (expected.format != "elf" || expected.code_id.is_some())
        && expected.architecture == identity["architecture"]
        && parsed.is_some()
        && parsed == actual
        && expected
            .code_id
            .as_ref()
            .is_none_or(|id| identity["code_id"] == id.to_lowercase())
}

struct BoundedCache(Vec<u8>);
impl Write for BoundedCache {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > 64 * 1024 * 1024 {
            return Err(io::Error::other("Cache budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn convert(object: &symbolic_debuginfo::Object<'_>) -> Result<Vec<u8>, ()> {
    let mut converter = SymCacheConverter::new();
    converter.process_object(object).map_err(|_| ())?;
    let mut cache = BoundedCache(Vec::new());
    converter.serialize(&mut cache).map_err(|_| ())?;
    SymCache::parse(&cache.0).map_err(|_| ())?;
    Ok(cache.0)
}

fn run() -> Result<Value, ()> {
    let arguments: Vec<_> = env::args().collect();
    if arguments.len() != 3 {
        return Err(());
    }
    let metadata = fs::read(&arguments[2]).map_err(|_| ())?;
    if metadata.len() > 65536 {
        return Err(());
    }
    let request: Request = serde_json::from_slice(&metadata).map_err(|_| ())?;
    if request.addresses.len() > 500
        || (!request.addresses.is_empty() && request.expected.is_none())
    {
        return Err(());
    }
    let data = fs::read(&arguments[1]).map_err(|_| ())?;
    if data.is_empty() || data.len() > 20 * 1024 * 1024 {
        return Err(());
    }
    let archive = Archive::parse(&data).map_err(|_| ())?;
    if !matches!(
        archive.file_format(),
        FileFormat::Elf | FileFormat::MachO | FileFormat::Pe | FileFormat::Pdb
    ) || archive.object_count() == 0
        || archive.object_count() > 16
    {
        return Err(());
    }
    let mut objects = Vec::new();
    let mut identities = Vec::new();
    for item in archive.objects() {
        let object = item.map_err(|_| ())?;
        let debug = object.debug_id();
        let code = object.code_id().map(|id| id.to_string());
        let format = object.file_format().to_string();
        let usable = !debug.uuid().is_nil()
            && object.arch().to_string() != "unknown"
            && (object.file_format() != FileFormat::Elf
                || code.as_ref().is_some_and(|id| !id.is_empty()));
        identities.push(
            json!({"format": format, "architecture": object.arch().to_string(),
            "debug_id": debug.to_string(), "code_id": code, "usable": usable,
            "has_debug_info": object.has_debug_info(), "has_symbols": object.has_symbols(),
            "preferred_load_address": format!("0x{:x}", object.load_address())}),
        );
        objects.push(object);
    }
    let selected = if let Some(expected) = &request.expected {
        let matches: Vec<_> = identities
            .iter()
            .enumerate()
            .filter(|(_, id)| id["usable"] == true && identity_matches(expected, id))
            .map(|(index, _)| index)
            .collect();
        if matches.len() != 1 {
            return Err(());
        }
        Some(matches[0])
    } else {
        None
    };
    if request.addresses.is_empty() {
        // Inspection validates debug content, not only a plausible object header.
        for object in &objects {
            if object.has_debug_info() {
                convert(object)?;
            }
        }
        return Ok(
            json!({"schema_version":1,"objects":identities,"selected":selected,"frames":[]}),
        );
    }
    let object = &objects[selected.ok_or(())?];
    // PE without embedded DWARF is inspection-only. Its separately uploaded PDB carries lines.
    if !object.has_debug_info() {
        return Err(());
    }
    let cache_data = convert(object)?;
    let cache = SymCache::parse(&cache_data).map_err(|_| ())?;
    let mut frames = Vec::new();
    for (index, raw) in request.addresses.iter().enumerate() {
        let address = raw
            .strip_prefix("0x")
            .filter(|s| !s.is_empty() && s.len() <= 8)
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .filter(|a| *a < u32::MAX as u64)
            .ok_or(())?;
        let mut locations = Vec::new();
        for location in cache.lookup(address) {
            if locations.len() == 32 {
                return Err(());
            }
            let function = location.function();
            let name = function
                .name_for_demangling()
                .demangle(DemangleOptions::complete())
                .unwrap_or_else(|| function.name().to_owned());
            let file = location.file().map(|file| file.full_path());
            if name.len() > 4096
                || function.name().len() > 4096
                || file.as_ref().is_some_and(|f| f.len() > 4096)
            {
                return Err(());
            }
            locations.push(json!({"function":name,"symbol":function.name(),"file":file,
                "line": if location.line() == 0 { None } else { Some(location.line()) },
                "function_address":if function.entry_pc() == u32::MAX { None } else { Some(format!("0x{:x}",function.entry_pc())) }}));
        }
        frames.push(json!({"index":index,"address":raw,"status":if locations.is_empty(){"unresolved"}else{"resolved"},"locations":locations}));
    }
    Ok(json!({"schema_version":1,"objects":identities,"selected":selected,"frames":frames}))
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(target_os = "linux")]
    {
        // Bound this parser child independently of the service's cgroup allocation.
        for (resource, value) in [
            (libc::RLIMIT_AS, 384 * 1024 * 1024),
            (libc::RLIMIT_CPU, 10),
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_NOFILE, 32),
        ] {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            if unsafe { libc::setrlimit(resource, &limit) } != 0 {
                std::process::exit(2);
            }
        }
    }
    match run().and_then(|result| serde_json::to_vec(&result).map_err(|_| ())) {
        Ok(bytes) if bytes.len() <= 1024 * 1024 => {
            if io::stdout().write_all(&bytes).is_err() {
                std::process::exit(2);
            }
        }
        _ => std::process::exit(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_debug_age_tail_instead_of_truncating_identity() {
        let expected = Expected {
            format: "pdb".into(),
            architecture: "x86_64".into(),
            debug_id: "397bb368-5b91-d8ae-4c4c-44205044422e-00000001ffff".into(),
            code_id: None,
        };
        let identity = json!({"format":"pdb","architecture":"x86_64","debug_id":"397bb368-5b91-d8ae-4c4c-44205044422e-1","code_id":null});
        assert!(!identity_matches(&expected, &identity));
    }

    #[test]
    fn canonical_and_breakpad_spellings_preserve_age() {
        let canonical = strict_debug_id("397bb368-5b91-d8ae-4c4c-44205044422e-1");
        assert!(canonical.is_some());
        assert_eq!(
            canonical,
            strict_debug_id("397BB3685B91D8AE4C4C44205044422E1")
        );
        assert_ne!(
            canonical,
            strict_debug_id("397bb368-5b91-d8ae-4c4c-44205044422e-2")
        );
        for invalid in [
            "397bb368-5b91-d8ae-4c4c-44205044422e-",
            "397bb368-5b91-d8ae-4c4c-44205044422e-000000001",
            "é",
        ] {
            assert!(strict_debug_id(invalid).is_none());
        }
    }
}
