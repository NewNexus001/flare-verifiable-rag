// enclave/enclave_grpc/src/attestation/tdx.rs
//
// Phase 12 (Prompt 221) — Intel TDX hardware attestation binding.
//
// Opens /dev/tdx-guest and issues TDX_CMD_GET_REPORT0 (TDCALL[TDG.MR.REPORT])
// to obtain a TDREPORT (1024 bytes) binding caller-supplied REPORTDATA (a
// nonce) to the TD's RTMR measurements.
//
// UAPI is byte-exact against the Linux source (fetched live from
// torvalds/linux: include/uapi/linux/tdx-guest.h):
//   TDX_REPORTDATA_LEN 64 · TDX_REPORT_LEN 1024
//   struct tdx_report_req { u8 reportdata[64]; u8 tdreport[1024]; }
//   #define TDX_CMD_GET_REPORT0 _IOWR('T', 1, struct tdx_report_req)
//
// The device exists ONLY inside an Intel TDX guest VM. Everywhere else the
// open fails and we FAIL CLOSED with a typed error — no fabricated quote.
#![allow(dead_code)]

use std::io;

/// ReportData length (TDX_REPORTDATA_LEN).
pub const TDX_REPORTDATA_LEN: usize = 64;
/// TDREPORT length (TDX_REPORT_LEN).
pub const TDX_REPORT_LEN: usize = 1024;

/// Byte-exact `struct tdx_report_req` (uapi/linux/tdx-guest.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TdxReportReq {
    pub reportdata: [u8; TDX_REPORTDATA_LEN],
    pub tdreport: [u8; TDX_REPORT_LEN],
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            reportdata: [0u8; TDX_REPORTDATA_LEN],
            tdreport: [0u8; TDX_REPORT_LEN],
        }
    }
}

/// Compute `_IOWR(type, nr, size)` exactly as the kernel macro does:
///   _IOC(dir=READ|WRITE, type, nr, size) = (3<<30) | (type<<8) | nr | (size<<16)
fn iowr(ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((3u64 << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

/// TDX_CMD_GET_REPORT0 — matches `_IOWR('T', 1, struct tdx_report_req)`.
const TDX_CMD_GET_REPORT0: libc::c_ulong = {
    let ty = b'T' as u64;
    let size = (TDX_REPORTDATA_LEN + TDX_REPORT_LEN) as u64;
    ((3u64 << 30) | (ty << 8) | 1 | (size << 16)) as libc::c_ulong
};

/// Typed failure for TEE device access — always fail-closed.
#[derive(Debug)]
pub enum TeeDeviceError {
    /// The /dev/tdx-guest device does not exist (not inside a TDX guest).
    DeviceNotFound,
    Open(io::Error),
    Ioctl(io::Error),
    /// SEV-SNP firmware error code (exitinfo2 bits[31:0], see psp-sev.h).
    Firmware(u32),
    /// Compile-time platform guard: non-Linux builds cannot access the device.
    UnsupportedPlatform(&'static str),
}

impl std::fmt::Display for TeeDeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeDeviceError::DeviceNotFound => write!(f, "no TEE device (/dev/tdx-guest) — not running inside an Intel TDX guest"),
            TeeDeviceError::Open(e) => write!(f, "failed to open /dev/tdx-guest: {e}"),
            TeeDeviceError::Ioctl(e) => write!(f, "TDX_CMD_GET_REPORT0 ioctl failed: {e}"),
            TeeDeviceError::Firmware(code) => write!(f, "SEV-SNP firmware error: {code} (see psp-sev.h)"),
            TeeDeviceError::UnsupportedPlatform(os) => write!(f, "TDX attestation unavailable on this platform ({os}); requires Linux + /dev/tdx-guest"),
        }
    }
}

impl std::error::Error for TeeDeviceError {}

#[cfg(target_os = "linux")]
fn get_tdreport_impl(reportdata: &[u8; TDX_REPORTDATA_LEN]) -> Result<[u8; TDX_REPORT_LEN], TeeDeviceError> {
    use std::os::fd::OwnedFd;
    use std::os::unix::io::AsRawFd;

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tdx-guest")
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                TeeDeviceError::DeviceNotFound
            } else {
                TeeDeviceError::Open(e)
            }
        })?;

    let mut req = TdxReportReq {
        reportdata: *reportdata,
        tdreport: [0u8; TDX_REPORT_LEN],
    };

    // SAFETY: req points to valid, aligned memory matching the kernel ABI
    // exactly; the fd is a real /dev/tdx-guest descriptor. The `as _` cast
    // matches libc::Ioctl per target (c_int on musl, c_ulong on glibc).
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TDX_CMD_GET_REPORT0 as _, &mut req) };
    if ret != 0 {
        return Err(TeeDeviceError::Ioctl(io::Error::last_os_error()));
    }
    drop(OwnedFd::from(fd));

    Ok(req.tdreport)
}

#[cfg(not(target_os = "linux"))]
fn get_tdreport_impl(_reportdata: &[u8; TDX_REPORTDATA_LEN]) -> Result<[u8; TDX_REPORT_LEN], TeeDeviceError> {
    Err(TeeDeviceError::UnsupportedPlatform(std::env::consts::OS))
}

/// Request a TDREPORT binding the given report-data nonce. Fail-closed.
pub fn get_tdreport(reportdata: &[u8; TDX_REPORTDATA_LEN]) -> Result<[u8; TDX_REPORT_LEN], TeeDeviceError> {
    get_tdreport_impl(reportdata)
}
