use std::path::Path;

/// Executable path for a pid. `None` when the process is gone or hidden.
pub fn image_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    if n > buf.len() {
        return None;
    }
    buf.truncate(n);
    let text = String::from_utf8(buf).ok()?;
    if text.is_empty() || !Path::new(&text).is_absolute() {
        return None;
    }
    Some(text)
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
}
