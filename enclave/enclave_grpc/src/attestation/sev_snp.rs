// enclave/enclave_grpc/src/attestation/sev_snp.rs
//
// Phase 12 (Prompt 222) — AMD SEV-SNP hardware attestation binding.
//
// Opens /dev/sev-guest and issues SNP_GET_EXT_REPORT to obtain the SEV-SNP
// attestation report (firmware-signed) plus the hypervisor-provided
// certificate blob (VCEK chain).
//
// UAPI is byte-exact against the Linux source (fetched live from
// torvalds/linux: include/uapi/linux/sev-guest.h):
//   SNP_REPORT_USER_DATA_SIZE 64
//   struct snp_report_req        { u8 user_data[64]; u32 vmpl; u8 rsvd[28]; }  // 96B
//   struct snp_report_resp       { u8 data[4000]; }
//   struct snp_guest_request_ioctl { u8 msg_version; u64 req_data;
//                                    u64 resp_data; u64 exitinfo2; }           // 32B
//   struct snp_ext_report_req    { snp_report_req data; u64 certs_address;
//                                  u32 certs_len; }                            // 112B
//   #define SNP_GET_EXT_REPORT _IOWR('S', 0x2, struct snp_guest_request_ioctl)
//
// The device exists ONLY inside an AMD SEV-SNP guest VM. Everywhere else the
// open fails and we FAIL CLOSED with a typed error — no fabricated report.
#![allow(dead_code)]

use std::io;

/// SNP_REPORT_USER_DATA_SIZE.
pub const SNP_USER_DATA_SIZE: usize = 64;
/// snp_report_resp.data capacity.
pub const SNP_RESP_DATA_LEN: usize = 4000;

/// Byte-exact `struct snp_report_req` (uapi/linux/sev-guest.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpReportReq {
    pub user_data: [u8; SNP_USER_DATA_SIZE],
    pub vmpl: u32,
    pub rsvd: [u8; 28],
}

impl Default for SnpReportReq {
    fn default() -> Self {
        Self {
            user_data: [0u8; SNP_USER_DATA_SIZE],
            vmpl: 0,
            rsvd: [0u8; 28],
        }
    }
}

/// Byte-exact `struct snp_report_resp`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpReportResp {
    pub data: [u8; SNP_RESP_DATA_LEN],
}

impl Default for SnpReportResp {
    fn default() -> Self {
        Self {
            data: [0u8; SNP_RESP_DATA_LEN],
        }
    }
}

/// Byte-exact `struct snp_guest_request_ioctl` (32 bytes with alignment).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpGuestRequestIoctl {
    pub msg_version: u8,
    pub _pad: [u8; 7],
    pub req_data: u64,
    pub resp_data: u64,
    pub exitinfo2: u64,
}

impl Default for SnpGuestRequestIoctl {
    fn default() -> Self {
        Self {
            msg_version: 1,
            _pad: [0u8; 7],
            req_data: 0,
            resp_data: 0,
            exitinfo2: 0,
        }
    }
}

/// Byte-exact `struct snp_ext_report_req` (112 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpExtReportReq {
    pub data: SnpReportReq,
    pub certs_address: u64,
    pub certs_len: u32,
    pub _pad: u32,
}

impl Default for SnpExtReportReq {
    fn default() -> Self {
        Self {
            data: SnpReportReq::default(),
            certs_address: 0,
            certs_len: 0,
            _pad: 0,
        }
    }
}

const fn iowr(ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((3u64 << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

/// SNP_GET_EXT_REPORT — `_IOWR('S', 0x2, struct snp_guest_request_ioctl)`.
const SNP_GET_EXT_REPORT: libc::c_ulong =
    iowr(b'S', 0x2, std::mem::size_of::<SnpGuestRequestIoctl>());

/// Typed failure for SEV-SNP device access — always fail-closed.
#[derive(Debug)]
pub enum SevGuestError {
    DeviceNotFound,
    Open(io::Error),
    Ioctl(io::Error),
    /// Firmware error code reported via exitinfo2 (see psp-sev.h).
    Firmware(u32),
    UnsupportedPlatform(&'static str),
}

impl std::fmt::Display for SevGuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SevGuestError::DeviceNotFound => write!(f, "no TEE device (/dev/sev-guest) — not running inside an AMD SEV-SNP guest"),
            SevGuestError::Open(e) => write!(f, "failed to open /dev/sev-guest: {e}"),
            SevGuestError::Ioctl(e) => write!(f, "SNP_GET_EXT_REPORT ioctl failed: {e}"),
            SevGuestError::Firmware(code) => write!(f, "SEV-SNP firmware error: {code} (see psp-sev.h)"),
            SevGuestError::UnsupportedPlatform(os) => write!(f, "SEV-SNP attestation unavailable on this platform ({os}); requires Linux + /dev/sev-guest"),
        }
    }
}

impl std::error::Error for SevGuestError {}

/// Convert to the common TEE error type so the gRPC handler can fall back
/// from TDX to SEV-SNP while preserving every failure reason (fail-closed).
impl From<SevGuestError> for super::tdx::TeeDeviceError {
    fn from(e: SevGuestError) -> Self {
        match e {
            SevGuestError::DeviceNotFound => super::tdx::TeeDeviceError::DeviceNotFound,
            SevGuestError::Open(err) => super::tdx::TeeDeviceError::Open(err),
            SevGuestError::Ioctl(err) => super::tdx::TeeDeviceError::Ioctl(err),
            SevGuestError::Firmware(code) => super::tdx::TeeDeviceError::Firmware(code),
            SevGuestError::UnsupportedPlatform(os) => super::tdx::TeeDeviceError::UnsupportedPlatform(os),
        }
    }
}

#[cfg(target_os = "linux")]
fn get_snp_report_impl(
    user_data: &[u8; SNP_USER_DATA_SIZE],
    certs: &mut [u8],
) -> Result<(Vec<u8>, Vec<u8>), SevGuestError> {
    use std::os::fd::OwnedFd;
    use std::os::unix::io::AsRawFd;

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                SevGuestError::DeviceNotFound
            } else {
                SevGuestError::Open(e)
            }
        })?;

    let mut resp = SnpReportResp::default();
    let mut req = SnpExtReportReq {
        data: SnpReportReq {
            user_data: *user_data,
            vmpl: 0,
            rsvd: [0u8; 28],
        },
        certs_address: certs.as_mut_ptr() as u64,
        certs_len: certs.len() as u32,
        _pad: 0,
    };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        ..SnpGuestRequestIoctl::default()
    };
    ioctl_req.req_data = (&mut req as *mut SnpExtReportReq) as u64;
    ioctl_req.resp_data = (&mut resp as *mut SnpReportResp) as u64;

    // SAFETY: both req_data/resp_data point at valid, aligned buffers whose
    // layouts match the kernel ABI exactly; the fd is a real /dev/sev-guest
    // descriptor; the ioctl ABI is documented in sev-guest.h. The `as _` cast
    // matches libc::Ioctl per target (c_int on musl, c_ulong on glibc).
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), SNP_GET_EXT_REPORT as _, &mut ioctl_req) };
    if ret != 0 {
        // exitinfo2: bits[31:0] firmware error, bits[63:32] VMM error.
        let fw_err = (ioctl_req.exitinfo2 & 0xFFFF_FFFF) as u32;
        if fw_err != 0 && fw_err != u32::MAX {
            return Err(SevGuestError::Firmware(fw_err));
        }
        return Err(SevGuestError::Ioctl(io::Error::last_os_error()));
    }
    drop(OwnedFd::from(fd));

    // The attestation report occupies the first bytes of resp.data (layout
    // per the SEV-SNP spec); certificates were copied to `certs`. Report the
    // actual cert length the kernel filled back.
    let cert_len = req.certs_len.min(certs.len() as u32) as usize;
    Ok((resp.data.to_vec(), certs[..cert_len].to_vec()))
}

#[cfg(not(target_os = "linux"))]
fn get_snp_report_impl(
    _user_data: &[u8; SNP_USER_DATA_SIZE],
    _certs: &mut [u8],
) -> Result<(Vec<u8>, Vec<u8>), SevGuestError> {
    Err(SevGuestError::UnsupportedPlatform(std::env::consts::OS))
}

/// Request the SEV-SNP attestation report + certificate blob. Fail-closed.
pub fn get_snp_attestation_report(
    user_data: &[u8; SNP_USER_DATA_SIZE],
    certs: &mut [u8],
) -> Result<(Vec<u8>, Vec<u8>), SevGuestError> {
    get_snp_report_impl(user_data, certs)
}
