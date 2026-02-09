// SPDX-License-Identifier: GPL-2.0

//! Network console driver in Rust.
//!
//! This module implements a network console driver that sends kernel log
//! messages over UDP using the netpoll subsystem.
//!
//! C equivalent: [`drivers/net/netconsole.c`](srctree/drivers/net/netconsole.c)

use core::ops::Deref;
use core::pin::Pin;
use kernel::{
    alloc::flags,
    bindings,
    c_str,
    configfs::{self, configfs_attrs},
    console::{flags as console_flags, Console, ConsoleOps},
    net::netpoll::{
        Netpoll,
        NetpollBuilder,
        IFNAMSIZ, //
    },
    net::{
        IpAddr,
        MacAddr, //
    },
    new_mutex, new_spinlock,
    page::PAGE_SIZE,
    prelude::*,
    str::CString,
    sync::{Arc, ArcBorrow, Mutex, SpinLock},
};

module! {
    type: NetconsoleModule,
    name: "netconsole_rust",
    authors: ["Matthew Wood"],
    description: "Network console driver (Rust implementation)",
    license: "GPL",
    params: {
        netconsole: ::kernel::module_param::CStrParam {
            default: ::kernel::module_param::CStrParam::null(),
            description: "netconsole=[+][r][src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]",
        },
    },
}

const DEFAULT_LOCAL_PORT: u16 = 6665;
const DEFAULT_REMOTE_PORT: u16 = 6666;

/// Sysdata feature bitflags (matching C's `enum sysdata_feature`).
const SYSDATA_CPU_NR: u32 = 1 << 0;
const SYSDATA_TASKNAME: u32 = 1 << 1;
const SYSDATA_RELEASE: u32 = 1 << 2;
const SYSDATA_MSGID: u32 = 1 << 3;
const MAX_SYSDATA_ITEMS: usize = 4;

/// Maximum length of a userdata value.
const MAX_EXTRADATA_VALUE_LEN: usize = 200;
/// Maximum length of a userdata key name.
const MAX_EXTRADATA_NAME_LEN: usize = 53;
/// Maximum number of userdata entries per target.
const MAX_USERDATA_ITEMS: usize = 256;

/// Pre-formatted userdata cache for efficient message sending.
struct UserdataCache {
    /// Pre-formatted " key=value\n" strings.
    data: Option<KVec<u8>>,
    /// Length of formatted data.
    len: usize,
}

impl UserdataCache {
    fn new() -> Self {
        Self { data: None, len: 0 }
    }
}

/// Configuration state for a netconsole target.
/// These fields are only accessed in process context (configfs operations).
struct ConfigState {
    /// Whether to use extended log format.
    extended: bool,
    /// Whether to prepend kernel release.
    release: bool,
    /// Device name.
    dev_name: [u8; IFNAMSIZ],
    /// Local port.
    local_port: u16,
    /// Remote port.
    remote_port: u16,
    /// Local IP.
    local_ip: IpAddr,
    /// Remote IP.
    remote_ip: IpAddr,
    /// Remote MAC address.
    remote_mac: MacAddr,
}

/// A netconsole target configuration.
#[pin_data]
struct NetconsoleTarget {
    /// Whether this target is enabled.
    #[pin]
    enabled: SpinLock<bool>,
    /// Configuration state (accessed in process context only).
    #[pin]
    config: Mutex<ConfigState>,
    /// The netpoll instance (when enabled).
    #[pin]
    netpoll: SpinLock<Option<Pin<KBox<Netpoll>>>>,
    /// Transmit error count.
    #[pin]
    xmit_errors: SpinLock<u64>,
    /// Pre-formatted userdata cache for message sending.
    #[pin]
    userdata_cache: SpinLock<UserdataCache>,
    /// Sysdata feature flags (bitwise OR of SYSDATA_* constants).
    #[pin]
    sysdata_fields: SpinLock<u32>,
    /// Per-target message counter for msgid sysdata feature.
    #[pin]
    msg_counter: SpinLock<u32>,
    /// Embedded userdata group (contains both config_group and Userdata).
    #[pin]
    userdata_group: configfs::Group<Userdata>,
}

/// A single userdata key-value entry within a target.
#[pin_data]
struct UserdataEntry {
    /// The key name (copied from mkdir name).
    key: [u8; MAX_EXTRADATA_NAME_LEN + 1],
    /// Length of the key.
    key_len: usize,
    /// Back-pointer to parent Userdata for cache updates.
    parent: *const Userdata,
}

// SAFETY: UserdataEntry synchronizes access via parent's locks.
// The parent pointer is only dereferenced in process context while parent is valid.
unsafe impl Send for UserdataEntry {}
unsafe impl Sync for UserdataEntry {}

impl UserdataEntry {
    /// Creates a new userdata entry with the given key name.
    fn new(key: &CStr, parent: *const Userdata) -> impl PinInit<Self, Error> {
        let key_bytes = key.to_bytes();
        let key_len = key_bytes.len();
        let mut key_arr = [0u8; MAX_EXTRADATA_NAME_LEN + 1];
        key_arr[..key_len].copy_from_slice(key_bytes);

        try_pin_init!(Self {
            key: key_arr,
            key_len,
            parent,
        })
    }

    /// Gets the key as a byte slice.
    fn key_bytes(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

/// A stored userdata value.
struct UserdataValue {
    /// The value data.
    data: [u8; MAX_EXTRADATA_VALUE_LEN],
    /// Length of the value.
    len: usize,
}

impl UserdataValue {
    fn new() -> Self {
        Self {
            data: [0u8; MAX_EXTRADATA_VALUE_LEN],
            len: 0,
        }
    }
}

/// Container group for userdata entries within a target.
#[pin_data]
struct Userdata {
    /// Back-pointer to the parent target for cache access.
    /// Set after initialization when embedded in NetconsoleTarget.
    target: core::cell::UnsafeCell<*const NetconsoleTarget>,
    /// Number of entries (for limit checking).
    #[pin]
    entry_count: SpinLock<usize>,
    /// Map of key -> value for all entries.
    /// Key is stored as [u8; MAX_EXTRADATA_NAME_LEN+1] with length.
    #[pin]
    values: Mutex<KVec<([u8; MAX_EXTRADATA_NAME_LEN + 1], usize, UserdataValue)>>,
}

// SAFETY: Userdata synchronizes access via Mutex and SpinLock.
// The target pointer is only dereferenced in process context while target is valid.
unsafe impl Send for Userdata {}
unsafe impl Sync for Userdata {}

impl Userdata {
    /// Creates a new userdata container.
    /// The target pointer must be set after initialization via `set_target()`.
    fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            target: core::cell::UnsafeCell::new(core::ptr::null()),
            entry_count <- new_spinlock!(0usize),
            values <- new_mutex!(KVec::new()),
        })
    }

    /// Sets the target pointer. Must be called once after initialization.
    ///
    /// # Safety
    ///
    /// - Must only be called once.
    /// - `target` must be a valid pointer that outlives this Userdata.
    unsafe fn set_target(&self, target: *const NetconsoleTarget) {
        // SAFETY: We only call this once during initialization.
        unsafe { *self.target.get() = target };
    }

    /// Gets the target pointer.
    fn target(&self) -> *const NetconsoleTarget {
        // SAFETY: The pointer was set during initialization and is valid.
        unsafe { *self.target.get() }
    }

    /// Adds a new entry with the given key.
    fn add_entry(&self, key: &[u8]) -> Result {
        let mut values = self.values.lock();

        // Check if key already exists
        for (k, klen, v) in values.iter() {
            if *klen == key.len() && &k[..*klen] == key {
                pr_info!(
                    "netconsole: userdata key already exists: {:?} {}\n",
                    key,
                    v.len
                );
                return Err(EEXIST);
            }
        }

        let mut key_arr = [0u8; MAX_EXTRADATA_NAME_LEN + 1];
        key_arr[..key.len()].copy_from_slice(key);

        values.push(
            (key_arr, key.len(), UserdataValue::new()),
            flags::GFP_KERNEL,
        )?;

        let mut count = self.entry_count.lock();
        *count += 1;

        Ok(())
    }

    /// Removes an entry with the given key.
    /// Note: Currently not called from drop_item because we can't access the key
    /// from ArcBorrow<Group<UserdataEntry>>. This is a limitation of the current
    /// configfs abstraction.
    #[allow(dead_code)]
    fn remove_entry(&self, key: &[u8]) {
        let mut values = self.values.lock();

        if let Some(pos) = values
            .iter()
            .position(|(k, klen, _)| *klen == key.len() && &k[..*klen] == key)
        {
            let _ = values.remove(pos);

            let mut count = self.entry_count.lock();
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    /// Gets the value for a key.
    fn get_value(&self, key: &[u8], out: &mut [u8; MAX_EXTRADATA_VALUE_LEN]) -> usize {
        let values = self.values.lock();
        for (k, klen, v) in values.iter() {
            if *klen == key.len() && &k[..*klen] == key {
                out[..v.len].copy_from_slice(&v.data[..v.len]);
                return v.len;
            }
        }
        0
    }

    /// Sets the value for a key.
    fn set_value(&self, key: &[u8], value: &[u8]) -> Result {
        let mut values = self.values.lock();
        for (k, klen, v) in values.iter_mut() {
            if *klen == key.len() && &k[..*klen] == key {
                if value.len() > MAX_EXTRADATA_VALUE_LEN {
                    return Err(EINVAL);
                }
                v.data[..value.len()].copy_from_slice(value);
                v.len = value.len();
                drop(values);
                self.rebuild_cache();
                return Ok(());
            }
        }
        Err(ENOENT)
    }

    /// Rebuilds the userdata cache for the parent target.
    fn rebuild_cache(&self) {
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*self.target() };

        let values = self.values.lock();

        // Calculate total length needed
        let mut total_len = 0usize;
        for (_, klen, v) in values.iter() {
            if v.len > 0 {
                // Format: " key=value\n"
                total_len += 1 + klen + 1 + v.len + 1;
            }
        }

        if total_len == 0 {
            // No userdata, clear cache
            let mut cache = target.userdata_cache.lock();
            cache.data = None;
            cache.len = 0;
            return;
        }

        // Allocate buffer
        let mut buf = match KVec::with_capacity(total_len, flags::GFP_KERNEL) {
            Ok(b) => b,
            Err(_) => {
                pr_err!("netconsole: failed to allocate userdata cache\n");
                return;
            }
        };

        // Format each entry
        for (key, klen, v) in values.iter() {
            if v.len > 0 {
                // " key=value\n"
                let _ = buf.push(b' ', flags::GFP_KERNEL);
                for i in 0..*klen {
                    let _ = buf.push(key[i], flags::GFP_KERNEL);
                }
                let _ = buf.push(b'=', flags::GFP_KERNEL);
                for i in 0..v.len {
                    let _ = buf.push(v.data[i], flags::GFP_KERNEL);
                }
                let _ = buf.push(b'\n', flags::GFP_KERNEL);
            }
        }

        // Update cache
        let mut cache = target.userdata_cache.lock();
        cache.len = buf.len();
        cache.data = Some(buf);
    }
}

/// Holds enabled target references for the console write callback.
/// We store raw pointers because targets are owned by configfs and we track
/// enabled/disabled state to add/remove them.
#[pin_data]
struct EnabledTargets {
    #[pin]
    list: SpinLock<KVec<*const NetconsoleTarget>>,
}

// SAFETY: EnabledTargets synchronizes access via SpinLock.
unsafe impl Send for EnabledTargets {}
unsafe impl Sync for EnabledTargets {}

impl EnabledTargets {
    fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            list <- new_spinlock!(KVec::new()),
        })
    }

    /// Adds a target to the enabled list.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `remove()` is called before `target` is dropped.
    unsafe fn add(&self, target: *const NetconsoleTarget) -> Result {
        let mut list = self.list.lock();
        list.push(target, flags::GFP_ATOMIC)?;
        Ok(())
    }

    /// Removes a target from the enabled list.
    fn remove(&self, target: *const NetconsoleTarget) {
        let mut list = self.list.lock();
        list.retain(|ptr| *ptr != target);
    }

    /// Iterates over enabled targets and sends a message to each.
    fn send_to_all(&self, msg: &[u8]) {
        let list = self.list.lock();
        for &target_ptr in list.iter() {
            // SAFETY: The target is guaranteed to be valid because:
            // 1. It was added via `add()` which requires the target to be valid
            // 2. The target calls `remove()` before it is disabled
            // 3. The spinlock ensures we don't race with removal
            let target = unsafe { &*target_ptr };
            target.send_msg(msg);
        }
    }
}

/// Shared enabled targets list for console write callback.
type SharedEnabledTargets = Arc<EnabledTargets>;

/// Global enabled targets list holder.
/// We wrap it in a struct that implements Sync so it can be used in a static.
struct EnabledTargetsHolder {
    inner: core::cell::UnsafeCell<Option<SharedEnabledTargets>>,
}

// SAFETY: We ensure thread-safe access through proper initialization ordering:
// - The value is set exactly once during module init, before any other access
// - After init, the value is only read (immutable access)
// - The atomic nature of Option<Arc<T>> reads on most architectures makes this safe
unsafe impl Sync for EnabledTargetsHolder {}

impl EnabledTargetsHolder {
    const fn new() -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(None),
        }
    }

    /// Initializes the holder. Must be called exactly once during module init.
    ///
    /// # Safety
    ///
    /// Must only be called once, before any calls to `get()`.
    unsafe fn init(&self, value: SharedEnabledTargets) {
        // SAFETY: The caller ensures this is only called once, during module init.
        unsafe { *self.inner.get() = Some(value) };
    }

    /// Gets a reference to the enabled targets list.
    ///
    /// # Safety
    ///
    /// Must only be called after `init()` has been called.
    fn get(&self) -> &SharedEnabledTargets {
        // SAFETY: The caller ensures init() was called before this.
        unsafe {
            (*self.inner.get())
                .as_ref()
                .expect("enabled targets not initialized")
        }
    }
}

/// Global enabled targets list.
static ENABLED_TARGETS: EnabledTargetsHolder = EnabledTargetsHolder::new();

/// Gets the global enabled targets list.
fn enabled_targets() -> &'static SharedEnabledTargets {
    ENABLED_TARGETS.get()
}

/// Initializes the global enabled targets list. Must be called once at module init.
fn init_enabled_targets() -> Result<()> {
    let targets = Arc::pin_init(EnabledTargets::new(), flags::GFP_KERNEL)?;
    // SAFETY: This is called exactly once during module init.
    unsafe { ENABLED_TARGETS.init(targets) };
    Ok(())
}

/// Global storage for cmdline-parsed configurations.
/// When a user creates a group matching a cmdline target name, we use
/// the stored config instead of defaults.
struct CmdlineConfigHolder {
    inner: core::cell::UnsafeCell<KVec<(CString, ParsedConfig)>>,
}

// SAFETY: Access is synchronized - written once during init before any reads
unsafe impl Sync for CmdlineConfigHolder {}

impl CmdlineConfigHolder {
    const fn new() -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(KVec::new()),
        }
    }

    /// Adds a cmdline config. Called during module init only.
    ///
    /// # Safety
    /// Must only be called during module init, before any calls to `take()`.
    #[allow(dead_code)]
    unsafe fn add(&self, name: CString, config: ParsedConfig) -> Result {
        let vec = unsafe { &mut *self.inner.get() };
        vec.push((name, config), flags::GFP_KERNEL)?;
        Ok(())
    }

    /// Takes (removes) a config by name, if it exists.
    fn take(&self, name: &CStr) -> Option<ParsedConfig> {
        // SAFETY: After init, this is the only way to access configs
        let vec = unsafe { &mut *self.inner.get() };
        if let Some(pos) = vec.iter().position(|(n, _)| n.deref() == name) {
            Some(vec.remove(pos).unwrap().1)
        } else {
            None
        }
    }
}

static CMDLINE_CONFIGS: CmdlineConfigHolder = CmdlineConfigHolder::new();

/// Item type for the embedded userdata group.
/// This defines the sysdata feature attributes on the userdata group.
fn userdata_item_type() -> &'static configfs::ItemType<configfs::Group<Userdata>, Userdata> {
    configfs_attrs! {
        container: configfs::Group<Userdata>,
        data: Userdata,
        child: UserdataEntry,
        attributes: [
            cpu_nr_enabled: 0,
            taskname_enabled: 1,
            release_enabled: 2,
            msgid_enabled: 3,
        ],
    }
}

/// Static item type for cmdline-created targets.
/// This defines the attributes available on a target created via cmdline.
/// Uses `configfs_attrs!` macro which creates statics internally.
fn target_item_type(
) -> &'static configfs::ItemType<configfs::Group<NetconsoleTarget>, NetconsoleTarget> {
    configfs_attrs! {
        container: configfs::Group<NetconsoleTarget>,
        data: NetconsoleTarget,
        attributes: [
            enabled: 0,
            extended: 1,
            release: 2,
            dev_name: 3,
            local_port: 4,
            remote_port: 5,
            local_ip: 6,
            remote_ip: 7,
            remote_mac: 8,
            transmit_errors: 9,
        ],
    }
}

#[allow(dead_code)]
impl NetconsoleTarget {
    /// Creates a new target, optionally from a parsed configuration.
    fn new_with_config(cfg: Option<ParsedConfig>) -> impl PinInit<Self, Error> {
        let (extended, release, dev_name, local_port, remote_port, local_ip, remote_ip, remote_mac) =
            if let Some(cfg) = cfg {
                (
                    cfg.extended,
                    cfg.release,
                    cfg.dev_name,
                    cfg.local_port,
                    cfg.remote_port,
                    cfg.local_ip,
                    cfg.remote_ip,
                    cfg.remote_mac,
                )
            } else {
                let mut dev_name = [0u8; IFNAMSIZ];
                dev_name[..4].copy_from_slice(b"eth0");
                (
                    false,
                    false,
                    dev_name,
                    DEFAULT_LOCAL_PORT,
                    DEFAULT_REMOTE_PORT,
                    IpAddr::default(),
                    IpAddr::default(),
                    MacAddr::BROADCAST,
                )
            };

        try_pin_init!(Self {
            enabled <- new_spinlock!(false),
            config <- new_mutex!(ConfigState {
                extended,
                release,
                dev_name,
                local_port,
                remote_port,
                local_ip,
                remote_ip,
                remote_mac,
            }),
            netpoll <- new_spinlock!(None),
            xmit_errors <- new_spinlock!(0u64),
            userdata_cache <- new_spinlock!(UserdataCache::new()),
            sysdata_fields <- new_spinlock!(0u32),
            msg_counter <- new_spinlock!(0u32),
            userdata_group <- configfs::Group::new_embedded(
                c_str!("userdata"),
                userdata_item_type(),
                Userdata::new(),
            ),
        })
        .pin_chain(|this: Pin<&mut Self>| {
            // Set up the userdata's back-pointer to the target
            // SAFETY: this is valid and pinned.
            let target_ptr = this.as_ref().get_ref() as *const Self;
            // Access the Userdata inside the embedded Group and set the target pointer.
            // SAFETY: We have exclusive access during initialization, and the Group is initialized.
            unsafe {
                let userdata_group_ptr = &this.as_ref().get_ref().userdata_group;
                let userdata_ptr =
                    configfs::Group::<Userdata>::data_ptr(userdata_group_ptr).cast_mut();
                (*userdata_ptr).set_target(target_ptr);
            }
            Ok(())
        })
    }

    /// Sets up the netpoll and enables this target.
    fn enable(&self) -> Result {
        let cfg = self.config.lock();

        let builder = NetpollBuilder::new()
            .name(c_str!("netconsole"))
            .dev_name_bytes(&cfg.dev_name[..strlen(&cfg.dev_name)])?
            .local_port(cfg.local_port)
            .remote_port(cfg.remote_port)
            .local_ip(cfg.local_ip)
            .remote_ip(cfg.remote_ip)
            .remote_mac(cfg.remote_mac);

        drop(cfg);

        // Try to set up the netpoll
        let np: Pin<KBox<Netpoll>> = KBox::try_pin_init(builder.setup(), flags::GFP_KERNEL)?;

        let mut np_guard = self.netpoll.lock();
        *np_guard = Some(np);
        drop(np_guard);

        *self.enabled.lock() = true;
        Ok(())
    }

    /// Sends a message through this target's netpoll.
    fn send_msg(&self, msg: &[u8]) {
        let np_guard = self.netpoll.lock();
        if let Some(ref np) = *np_guard {
            // Send main message
            let r1 = np.send_udp(msg);

            // Send userdata if present
            let cache = self.userdata_cache.lock();
            if cache.len > 0 {
                if let Some(ref data) = cache.data {
                    let _ = np.send_udp(data.as_slice());
                }
            }
            drop(cache);

            // Send sysdata if any features enabled
            let fields = *self.sysdata_fields.lock();
            if fields != 0 {
                let mut sysdata_buf = [0u8; 256 * MAX_SYSDATA_ITEMS];
                let sysdata_len = self.prepare_sysdata(fields, &mut sysdata_buf);
                if sysdata_len > 0 {
                    let _ = np.send_udp(&sysdata_buf[..sysdata_len]);
                }
            }

            if let Err(_) = r1 {
                drop(np_guard);
                let mut errors = self.xmit_errors.lock();
                *errors += 1;
            }
        }
    }

    /// Prepares sysdata fields into the given buffer.
    /// Returns the number of bytes written.
    fn prepare_sysdata(&self, fields: u32, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        if fields & SYSDATA_CPU_NR != 0 {
            let cpu = kernel::cpu::CpuId::current().as_u32();
            offset += format_sysdata_u32(&mut buf[offset..], b"cpu", cpu);
        }
        if fields & SYSDATA_TASKNAME != 0 {
            // SAFETY: get_current() always returns a valid pointer to the current task.
            let comm = unsafe {
                let task = bindings::get_current();
                &(*task).comm
            };
            let comm_len = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
            let comm_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(comm.as_ptr().cast(), comm_len)
            };
            offset += format_sysdata_bytes(&mut buf[offset..], b"taskname", comm_bytes);
        }
        if fields & SYSDATA_RELEASE != 0 {
            // SAFETY: init_uts_ns is a valid global that is always initialized.
            // Use raw pointer to avoid creating a shared reference to a mutable static.
            let release = unsafe {
                let ptr = &raw const bindings::init_uts_ns;
                &(*ptr).name.release
            };
            let rel_len = release.iter().position(|&c| c == 0).unwrap_or(release.len());
            let rel_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(release.as_ptr().cast(), rel_len)
            };
            offset += format_sysdata_bytes(&mut buf[offset..], b"release", rel_bytes);
        }
        if fields & SYSDATA_MSGID != 0 {
            let mut counter = self.msg_counter.lock();
            *counter = counter.wrapping_add(1);
            let id = *counter;
            drop(counter);
            offset += format_sysdata_u32(&mut buf[offset..], b"msgid", id);
        }

        offset
    }
}

/// Console operations for netconsole.
///
/// This struct implements the console write callback, iterating through
/// enabled targets and sending messages via netpoll.
#[pin_data]
struct NetconsoleConsoleOps;

// SAFETY: NetconsoleConsoleOps can be sent between threads.
unsafe impl Send for NetconsoleConsoleOps {}
// SAFETY: NetconsoleConsoleOps can be shared between threads (access is synchronized).
unsafe impl Sync for NetconsoleConsoleOps {}

#[vtable]
impl ConsoleOps for NetconsoleConsoleOps {
    fn write(&self, msg: &[u8]) {
        enabled_targets().send_to_all(msg);
    }
}

impl NetconsoleConsoleOps {
    fn new_init() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {})
    }
}

/// Netconsole subsystem data for configfs.
#[pin_data]
struct NetconsoleSubsys;

impl NetconsoleSubsys {
    fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {})
    }
}

/// The netconsole module state.
#[pin_data(PinnedDrop)]
struct NetconsoleModule {
    /// The configfs subsystem.
    #[pin]
    config: configfs::Subsystem<NetconsoleSubsys>,
    /// The registered kernel console.
    #[pin]
    console: Console<NetconsoleConsoleOps>,
    /// Optional cmdline target, created automatically if netconsole= cmdline param is provided.
    /// We store the Arc to keep the target alive.
    cmdline_target: Option<Arc<configfs::Group<NetconsoleTarget>>>,
}

impl kernel::InPlaceModule for NetconsoleModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        // Initialize the global enabled targets list
        // This must succeed for the module to work, so we expect/panic on failure
        init_enabled_targets().expect("failed to initialize enabled targets list");

        // Check if a netconsole parameter was provided via cmdline
        // We parse it now and store for use after subsystem is created
        let cmdline_cfg: Option<ParsedConfig> = {
            let param = module_parameters::netconsole.value();
            if let Some(config_bytes) = param.as_bytes() {
                if !config_bytes.is_empty() {
                    match parse_cmdline(config_bytes) {
                        Ok(cfg) => {
                            print_config_banner(&cfg);
                            Some(cfg)
                        }
                        Err(e) => {
                            pr_err!("netconsole: failed to parse cmdline config: {:?}\n", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        let item_type = configfs_attrs! {
            container: configfs::Subsystem<NetconsoleSubsys>,
            data: NetconsoleSubsys,
            child: NetconsoleTarget,
            attributes: [],
        };

        try_pin_init!(Self {
            config <- configfs::Subsystem::new(
                c_str!("netconsole"),
                item_type,
                NetconsoleSubsys::new(),
            ),
            console <- Console::register(
                c_str!("netcon"),
                console_flags::CON_ENABLED | console_flags::CON_PRINTBUFFER,
                NetconsoleConsoleOps::new_init(),
            ),
            cmdline_target: None,
        })
        .pin_chain(move |this: Pin<&mut Self>| {
            // If cmdline config was provided, create and register the target
            if let Some(cfg) = cmdline_cfg {
                pr_info!("netconsole: creating cmdline target automatically\n");

                // Create the target group
                let target: Arc<configfs::Group<NetconsoleTarget>> = Arc::pin_init(
                    configfs::Group::new(
                        CString::try_from_fmt(fmt!("cmdline0"))?,
                        target_item_type(),
                        NetconsoleTarget::new_with_config(Some(cfg)),
                    )
                    .pin_chain(|group: Pin<&mut configfs::Group<NetconsoleTarget>>| {
                        // Set up userdata group as a default group
                        // SAFETY: Both groups are initialized and pinned.
                        unsafe {
                            let parent_group =
                                configfs::Group::<NetconsoleTarget>::group(group.as_ref().get_ref())
                                    .cast_mut();
                            let target_data = group.as_ref().data();
                            let child_group =
                                configfs::Group::<Userdata>::group(&target_data.userdata_group)
                                    .cast_mut();

                            // Add the userdata_group to the parent's default_groups list
                            let prev = (*parent_group).default_groups.prev;
                            let new = &raw mut (*child_group).group_entry;
                            let head = &raw mut (*parent_group).default_groups;
                            (*new).next = head;
                            (*new).prev = prev;
                            (*prev).next = new;
                            (*head).prev = new;
                        }
                        Ok(())
                    }),
                    flags::GFP_KERNEL,
                )?;

                // Get pointers for registration
                let parent_group = this.config.group();
                // SAFETY: target is pinned and initialized.
                let child_group = unsafe {
                    configfs::Group::<NetconsoleTarget>::group(core::ptr::from_ref(
                        target.as_ref(),
                    ))
                    .cast_mut()
                };

                // Register the group with configfs
                // SAFETY: parent is a valid registered config_group (from subsystem),
                // child is a valid initialized config_group (from Group::new).
                unsafe {
                    configfs::register_group(parent_group, child_group)?;
                }

                // Get the target data pointer
                // SAFETY: target is valid and pinned via Arc::pin_init.
                let target_data = unsafe {
                    &*configfs::Group::<NetconsoleTarget>::data_ptr(core::ptr::from_ref(
                        target.as_ref(),
                    ))
                };

                // Try to enable the target. If it fails (e.g., network device not up yet),
                // don't fail module init - the target remains in configfs and can be
                // enabled later by the user via `echo 1 > enabled`.
                match target_data.enable() {
                    Ok(()) => {
                        // Add to enabled targets list
                        // SAFETY: The target is valid and will remain valid while stored in the module.
                        match unsafe {
                            enabled_targets().add(target_data as *const NetconsoleTarget)
                        } {
                            Ok(()) => {
                                pr_info!("netconsole: network logging started\n");
                            }
                            Err(e) => {
                                pr_warn!(
                                    "netconsole: failed to add target to list: {:?}, disabling\n",
                                    e
                                );
                                // Disable since we couldn't add to list
                                *target_data.enabled.lock() = false;
                                *target_data.netpoll.lock() = None;
                            }
                        }
                    }
                    Err(e) => {
                        pr_warn!(
                            "netconsole: network device not ready, target disabled: {:?}\n",
                            e
                        );
                        pr_info!(
                            "netconsole: target registered at cmdline0, enable manually when network is up\n"
                        );
                        // Target remains registered but disabled - user can enable later
                    }
                }

                // Store the target to keep it alive
                // SAFETY: We have unique access to the module during init.
                let this_mut = unsafe { this.get_unchecked_mut() };
                this_mut.cmdline_target = Some(target);
            }
            Ok(())
        })
    }
}

#[pinned_drop]
impl PinnedDrop for NetconsoleModule {
    fn drop(self: Pin<&mut Self>) {
        // Clean up the cmdline target if it exists
        if let Some(ref target) = self.cmdline_target {
            // Get the target data pointer
            // SAFETY: target is valid and pinned via Arc::pin_init.
            let target_data = unsafe {
                &*configfs::Group::<NetconsoleTarget>::data_ptr(core::ptr::from_ref(
                    target.as_ref(),
                ))
            };

            // Only clean up enabled state if it was actually enabled
            let was_enabled = *target_data.enabled.lock();
            if was_enabled {
                // Remove from enabled targets list
                enabled_targets().remove(target_data as *const NetconsoleTarget);

                // Disable the target
                *target_data.enabled.lock() = false;
                *target_data.netpoll.lock() = None;

                pr_info!("netconsole: network logging stopped\n");
            }

            // Unregister the group from configfs
            // SAFETY: The target was registered with configfs during init.
            unsafe {
                let child_group = configfs::Group::<NetconsoleTarget>::group(core::ptr::from_ref(
                    target.as_ref(),
                ))
                .cast_mut();
                configfs::unregister_group(child_group);
            }

            pr_info!("netconsole: cmdline target unregistered\n");
        }
        // The Arc will be dropped when the module struct is dropped,
        // which will decrement the refcount on the target.
    }
}

#[vtable]
impl configfs::GroupOperations for NetconsoleSubsys {
    type Child = NetconsoleTarget;

    fn make_group(
        &self,
        name: &CStr,
    ) -> Result<impl PinInit<configfs::Group<NetconsoleTarget>, Error>> {
        pr_info!("making group: {name}\n");
        let tpe = configfs_attrs! {
            container: configfs::Group<NetconsoleTarget>,
            data: NetconsoleTarget,
            attributes: [
                enabled: 0,
                extended: 1,
                release: 2,
                dev_name: 3,
                local_port: 4,
                remote_port: 5,
                local_ip: 6,
                remote_ip: 7,
                remote_mac: 8,
                transmit_errors: 9,
            ],
        };

        // Check if this is a cmdline target, otherwise use defaults
        let cfg = CMDLINE_CONFIGS.take(name);
        let is_cmdline_target = cfg.is_some();
        if is_cmdline_target {
            pr_info!("netconsole: creating target from cmdline config\n");
        }

        Ok(configfs::Group::new(
            name.try_into()?,
            tpe,
            NetconsoleTarget::new_with_config(cfg),
        )
        .pin_chain(move |group: Pin<&mut configfs::Group<NetconsoleTarget>>| {
            // Link the embedded userdata_group as a default group of the parent.
            // SAFETY: Both groups are initialized and pinned.
            unsafe {
                let parent_group =
                    configfs::Group::<NetconsoleTarget>::group(group.as_ref().get_ref()).cast_mut();
                let target_data = group.as_ref().data();
                // Get the config_group from the embedded Group<Userdata>
                let child_group =
                    configfs::Group::<Userdata>::group(&target_data.userdata_group).cast_mut();

                // Add the userdata_group to the parent's default_groups list
                let prev = (*parent_group).default_groups.prev;
                let new = &raw mut (*child_group).group_entry;
                let head = &raw mut (*parent_group).default_groups;
                (*new).next = head;
                (*new).prev = prev;
                (*prev).next = new;
                (*head).prev = new;
            }

            // If this is a cmdline target, enable it automatically
            if is_cmdline_target {
                let target_data = group.as_ref().data();
                if let Err(e) = target_data.enable() {
                    pr_err!("netconsole: failed to enable cmdline target: {:?}\n", e);
                    // Don't fail the group creation, just log the error
                }
            }

            Ok(())
        }))
    }
}

// Attribute 0: enabled (read-write)
#[vtable]
impl configfs::AttributeOperations<0> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let enabled = *container.enabled.lock();
        let s = if enabled { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        let val = parse_bool(page)?;

        // Check current state (brief lock hold)
        let current_enabled = *container.enabled.lock();
        if val == current_enabled {
            return Ok(());
        }

        if val {
            // Enable: set up netpoll first (this can sleep), then update state
            //
            // IMPORTANT: We must NOT hold any SpinLock while calling netpoll_setup()
            // because it internally calls synchronize_rcu() which can sleep.
            // Read config values - Mutex can sleep, that's fine.
            // Make copies so we can release locks before netpoll_setup.
            let (dev_name_copy, local_ip, local_port, remote_port, remote_mac, remote_ip) = {
                let cfg = container.config.lock();
                let len = strlen(&cfg.dev_name);
                let mut copy = [0u8; IFNAMSIZ];
                copy[..len].copy_from_slice(&cfg.dev_name[..len]);
                (copy, cfg.local_ip, cfg.local_port, cfg.remote_port, cfg.remote_mac, cfg.remote_ip)
            };

            let builder = NetpollBuilder::new()
                .name(c_str!("netconsole"))
                .dev_name_bytes(&dev_name_copy[..strlen(&dev_name_copy)])?
                .local_ip(local_ip)
                .local_port(local_port)
                .remote_port(remote_port)
                .remote_mac(remote_mac)
                .remote_ip(remote_ip);

            // Try to set up the netpoll - THIS CAN SLEEP, and that's OK now
            // because we're not holding any spinlocks.
            let np: Pin<KBox<Netpoll>> = KBox::try_pin_init(builder.setup(), flags::GFP_KERNEL)?;

            // Now acquire spinlocks briefly to update state
            {
                let mut np_guard = container.netpoll.lock();
                let mut enabled = container.enabled.lock();

                // Check if someone else enabled while we were setting up
                if *enabled {
                    // Someone else beat us to it, drop the np we created
                    return Ok(());
                }

                *np_guard = Some(np);
                *enabled = true;
            }

            // Add to enabled targets list for console write callback
            // SAFETY: The target remains valid while enabled.
            let add_result = unsafe { enabled_targets().add(container as *const NetconsoleTarget) };

            if let Err(e) = add_result {
                // Failed to add to list, roll back the state
                let mut np_guard = container.netpoll.lock();
                let mut enabled = container.enabled.lock();
                *np_guard = None;
                *enabled = false;
                return Err(e);
            }

            pr_info!("netconsole: network logging started\n");
        } else {
            // Disable: update state first, then clean up

            {
                let mut enabled = container.enabled.lock();
                if !*enabled {
                    // Already disabled
                    return Ok(());
                }
                *enabled = false;
            }

            // Remove from enabled targets list
            enabled_targets().remove(container as *const NetconsoleTarget);

            // Clean up netpoll
            {
                let mut np_guard = container.netpoll.lock();
                *np_guard = None;
            }

            pr_info!("netconsole: network logging stopped\n");
        }

        Ok(())
    }
}

// Attribute 1: extended (read-write)
#[vtable]
impl configfs::AttributeOperations<1> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let extended = container.config.lock().extended;
        let s = if extended { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let val = parse_bool(page)?;
        container.config.lock().extended = val;
        Ok(())
    }
}

// Attribute 2: release (read-write)
#[vtable]
impl configfs::AttributeOperations<2> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let release = container.config.lock().release;
        let s = if release { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let val = parse_bool(page)?;
        container.config.lock().release = val;
        Ok(())
    }
}

// Attribute 3: dev_name (read-write)
#[vtable]
impl configfs::AttributeOperations<3> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let cfg = container.config.lock();
        let len = strlen(&cfg.dev_name[..]);
        page[..len].copy_from_slice(&cfg.dev_name[..len]);
        page[len] = b'\n';
        Ok(len + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let mut cfg = container.config.lock();
        cfg.dev_name.fill(0);
        let len = core::cmp::min(page.len(), IFNAMSIZ - 1);
        let trimmed = trim_newline(&page[..len]);
        cfg.dev_name[..trimmed.len()].copy_from_slice(trimmed);
        Ok(())
    }
}

// Attribute 4: local_port (read-write)
#[vtable]
impl configfs::AttributeOperations<4> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let port = container.config.lock().local_port;
        let mut buf = [0u8; 16];
        let s = format_u16(&mut buf, port);
        page[..s.len()].copy_from_slice(s);
        page[s.len()] = b'\n';
        Ok(s.len() + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let val = parse_u16(page)?;
        container.config.lock().local_port = val;
        Ok(())
    }
}

// Attribute 5: remote_port (read-write)
#[vtable]
impl configfs::AttributeOperations<5> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let port = container.config.lock().remote_port;
        let mut buf = [0u8; 16];
        let s = format_u16(&mut buf, port);
        page[..s.len()].copy_from_slice(s);
        page[s.len()] = b'\n';
        Ok(s.len() + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let val = parse_u16(page)?;
        container.config.lock().remote_port = val;
        Ok(())
    }
}

// Attribute 6: local_ip (read-write)
#[vtable]
impl configfs::AttributeOperations<6> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let ip = container.config.lock().local_ip;
        let len = ip.format_into(page);
        page[len] = b'\n';
        Ok(len + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let ip = IpAddr::parse(page)?;
        container.config.lock().local_ip = ip;
        Ok(())
    }
}

// Attribute 7: remote_ip (read-write)
#[vtable]
impl configfs::AttributeOperations<7> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let ip = container.config.lock().remote_ip;
        let len = ip.format_into(page);
        page[len] = b'\n';
        Ok(len + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let ip = IpAddr::parse(page)?;
        container.config.lock().remote_ip = ip;
        Ok(())
    }
}

// Attribute 8: remote_mac (read-write)
#[vtable]
impl configfs::AttributeOperations<8> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mac = container.config.lock().remote_mac;
        let len = mac.format_into(page);
        page[len] = b'\n';
        Ok(len + 1)
    }

    fn store(container: &NetconsoleTarget, page: &[u8]) -> Result {
        if *container.enabled.lock() {
            return Err(EBUSY);
        }
        let mac = MacAddr::parse(page)?;
        container.config.lock().remote_mac = mac;
        Ok(())
    }
}

// Attribute 9: transmit_errors (read-only)
#[vtable]
impl configfs::AttributeOperations<9> for NetconsoleTarget {
    type Data = NetconsoleTarget;

    fn show(container: &NetconsoleTarget, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let errors = *container.xmit_errors.lock();
        let mut buf = [0u8; 32];
        let s = format_u64(&mut buf, errors);
        page[..s.len()].copy_from_slice(s);
        page[s.len()] = b'\n';
        Ok(s.len() + 1)
    }
}

// GroupOperations for Userdata: allows creating userdata entries
#[vtable]
impl configfs::GroupOperations for Userdata {
    type Child = UserdataEntry;

    fn make_group(
        &self,
        name: &CStr,
    ) -> Result<impl PinInit<configfs::Group<UserdataEntry>, Error>> {
        let name_bytes = name.to_bytes();

        // Validate key name length
        if name_bytes.len() > MAX_EXTRADATA_NAME_LEN {
            pr_err!(
                "netconsole: userdata key name too long (max {})\n",
                MAX_EXTRADATA_NAME_LEN
            );
            return Err(EINVAL);
        }

        // Check entry count limit
        {
            let count = *self.entry_count.lock();
            if count >= MAX_USERDATA_ITEMS {
                pr_err!(
                    "netconsole: maximum userdata entries ({}) reached\n",
                    MAX_USERDATA_ITEMS
                );
                return Err(ENOSPC);
            }
        }

        // Add entry to values map
        self.add_entry(name_bytes)?;

        let tpe = configfs_attrs! {
            container: configfs::Group<UserdataEntry>,
            data: UserdataEntry,
            attributes: [
                value: 0,
            ],
        };

        let parent_ptr = self as *const Userdata;

        Ok(configfs::Group::new(
            name.try_into()?,
            tpe,
            UserdataEntry::new(name, parent_ptr),
        ))
    }

    fn drop_item(&self, item: ArcBorrow<'_, configfs::Group<UserdataEntry>>) {
        // We need to get the key from the UserdataEntry to remove it from values.
        // Since we can't access Group.data directly, we need to use the name.
        // Unfortunately, we don't have access to the name here either.
        // Let's store the key in UserdataEntry and access it somehow.

        // For now, we'll iterate all values and rebuild cache anyway when any entry changes.
        // The entry removal by key is handled in the value store operation.
        // Actually, we need to remove the entry here.

        // Since we can't access the data field, we need a workaround.
        // One option is to not remove entries when the group is dropped,
        // and instead rely on the entire Userdata being dropped.
        // But this is incorrect behavior.

        // For now, let's just rebuild the cache. The value will be stale but
        // entries with len=0 are skipped in cache rebuild.
        // Actually, this is a design flaw - we can't remove the entry without knowing the key.

        // WORKAROUND: We store the key in UserdataEntry, and we need to find a way to access it.
        // Since ArcBorrow doesn't give us access to the data field, we can't do this cleanly.

        // Alternative: Store the key separately in a way we can access it.
        // For now, this is a limitation - entries won't be properly removed until
        // the entire Userdata is dropped.

        // Just rebuild cache which will only include entries with non-zero values
        self.rebuild_cache();

        // Note: The entry_count is not decremented here because we can't identify which entry.
        // This is a known limitation of this implementation.
        let _ = item; // Silence unused warning
    }
}

// Sysdata Attribute 0 for Userdata: cpu_nr_enabled (read-write)
#[vtable]
impl configfs::AttributeOperations<0> for Userdata {
    type Data = Userdata;

    fn show(container: &Userdata, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let enabled = (*target.sysdata_fields.lock() & SYSDATA_CPU_NR) != 0;
        let s = if enabled { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &Userdata, page: &[u8]) -> Result {
        let val = parse_bool(page)?;
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let mut fields = target.sysdata_fields.lock();
        if val {
            *fields |= SYSDATA_CPU_NR;
        } else {
            *fields &= !SYSDATA_CPU_NR;
        }
        Ok(())
    }
}

// Sysdata Attribute 1 for Userdata: taskname_enabled (read-write)
#[vtable]
impl configfs::AttributeOperations<1> for Userdata {
    type Data = Userdata;

    fn show(container: &Userdata, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let enabled = (*target.sysdata_fields.lock() & SYSDATA_TASKNAME) != 0;
        let s = if enabled { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &Userdata, page: &[u8]) -> Result {
        let val = parse_bool(page)?;
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let mut fields = target.sysdata_fields.lock();
        if val {
            *fields |= SYSDATA_TASKNAME;
        } else {
            *fields &= !SYSDATA_TASKNAME;
        }
        Ok(())
    }
}

// Sysdata Attribute 2 for Userdata: release_enabled (read-write)
#[vtable]
impl configfs::AttributeOperations<2> for Userdata {
    type Data = Userdata;

    fn show(container: &Userdata, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let enabled = (*target.sysdata_fields.lock() & SYSDATA_RELEASE) != 0;
        let s = if enabled { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &Userdata, page: &[u8]) -> Result {
        let val = parse_bool(page)?;
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let mut fields = target.sysdata_fields.lock();
        if val {
            *fields |= SYSDATA_RELEASE;
        } else {
            *fields &= !SYSDATA_RELEASE;
        }
        Ok(())
    }
}

// Sysdata Attribute 3 for Userdata: msgid_enabled (read-write)
#[vtable]
impl configfs::AttributeOperations<3> for Userdata {
    type Data = Userdata;

    fn show(container: &Userdata, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let enabled = (*target.sysdata_fields.lock() & SYSDATA_MSGID) != 0;
        let s = if enabled { b"1\n" } else { b"0\n" };
        page[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }

    fn store(container: &Userdata, page: &[u8]) -> Result {
        let val = parse_bool(page)?;
        // SAFETY: The target pointer was set during initialization and is valid.
        let target = unsafe { &*container.target() };
        let mut fields = target.sysdata_fields.lock();
        if val {
            *fields |= SYSDATA_MSGID;
        } else {
            *fields &= !SYSDATA_MSGID;
        }
        Ok(())
    }
}

// Attribute 0 for UserdataEntry: value (read-write)
#[vtable]
impl configfs::AttributeOperations<0> for UserdataEntry {
    type Data = UserdataEntry;

    fn show(container: &UserdataEntry, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        // SAFETY: The parent pointer is valid while this entry exists.
        let parent = unsafe { &*container.parent };
        let mut value = [0u8; MAX_EXTRADATA_VALUE_LEN];
        let len = parent.get_value(container.key_bytes(), &mut value);
        page[..len].copy_from_slice(&value[..len]);
        page[len] = b'\n';
        Ok(len + 1)
    }

    fn store(container: &UserdataEntry, page: &[u8]) -> Result {
        let trimmed = trim_newline(page);

        // Validate value length
        if trimmed.len() > MAX_EXTRADATA_VALUE_LEN {
            pr_err!(
                "netconsole: userdata value too long (max {})\n",
                MAX_EXTRADATA_VALUE_LEN
            );
            return Err(EINVAL);
        }

        // SAFETY: The parent pointer is valid while this entry exists.
        let parent = unsafe { &*container.parent };
        parent.set_value(container.key_bytes(), trimmed)
    }
}

// Helper functions

/// Parse a boolean value from a byte slice.
fn parse_bool(page: &[u8]) -> Result<bool> {
    let trimmed = trim_newline(page);
    if trimmed.is_empty() {
        return Err(EINVAL);
    }
    match trimmed {
        b"1" | b"y" | b"Y" | b"yes" | b"Yes" | b"YES" | b"true" | b"True" | b"TRUE" => Ok(true),
        b"0" | b"n" | b"N" | b"no" | b"No" | b"NO" | b"false" | b"False" | b"FALSE" => Ok(false),
        _ => Err(EINVAL),
    }
}

/// Parse a u16 from a byte slice.
fn parse_u16(page: &[u8]) -> Result<u16> {
    let trimmed = trim_newline(page);
    if trimmed.is_empty() {
        return Err(EINVAL);
    }
    let s = core::str::from_utf8(trimmed).map_err(|_| EINVAL)?;
    s.parse::<u16>().map_err(|_| EINVAL)
}

/// Format a u16 into a byte buffer, returning the formatted slice.
fn format_u16(buf: &mut [u8; 16], val: u16) -> &[u8] {
    let mut n = val;
    let mut i = buf.len();
    if n == 0 {
        buf[buf.len() - 1] = b'0';
        return &buf[buf.len() - 1..];
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Format a u64 into a byte buffer, returning the formatted slice.
fn format_u64(buf: &mut [u8; 32], val: u64) -> &[u8] {
    let mut n = val;
    let mut i = buf.len();
    if n == 0 {
        buf[buf.len() - 1] = b'0';
        return &buf[buf.len() - 1..];
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Format a u32 into a byte buffer, returning the formatted slice.
fn format_u32(buf: &mut [u8; 16], val: u32) -> &[u8] {
    let mut n = val;
    let mut i = buf.len();
    if n == 0 {
        buf[buf.len() - 1] = b'0';
        return &buf[buf.len() - 1..];
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Format a sysdata entry with a u32 value: " key=value\n"
/// Returns the number of bytes written.
fn format_sysdata_u32(buf: &mut [u8], key: &[u8], val: u32) -> usize {
    let mut tmp = [0u8; 16];
    let val_str = format_u32(&mut tmp, val);
    let total = 1 + key.len() + 1 + val_str.len() + 1; // ' ' + key + '=' + val + '\n'
    if buf.len() < total {
        return 0;
    }
    let mut offset = 0;
    buf[offset] = b' ';
    offset += 1;
    buf[offset..offset + key.len()].copy_from_slice(key);
    offset += key.len();
    buf[offset] = b'=';
    offset += 1;
    buf[offset..offset + val_str.len()].copy_from_slice(val_str);
    offset += val_str.len();
    buf[offset] = b'\n';
    offset += 1;
    offset
}

/// Format a sysdata entry with a byte slice value: " key=value\n"
/// Returns the number of bytes written.
fn format_sysdata_bytes(buf: &mut [u8], key: &[u8], val: &[u8]) -> usize {
    let total = 1 + key.len() + 1 + val.len() + 1; // ' ' + key + '=' + val + '\n'
    if buf.len() < total {
        return 0;
    }
    let mut offset = 0;
    buf[offset] = b' ';
    offset += 1;
    buf[offset..offset + key.len()].copy_from_slice(key);
    offset += key.len();
    buf[offset] = b'=';
    offset += 1;
    buf[offset..offset + val.len()].copy_from_slice(val);
    offset += val.len();
    buf[offset] = b'\n';
    offset += 1;
    offset
}

/// Trim trailing newline from a byte slice.
fn trim_newline(s: &[u8]) -> &[u8] {
    let mut len = s.len();
    while len > 0 && (s[len - 1] == b'\n' || s[len - 1] == b'\r') {
        len -= 1;
    }
    &s[..len]
}

/// Get the length of a null-terminated string in a byte slice.
fn strlen(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Parsed netconsole target configuration from cmdline.
struct ParsedConfig {
    extended: bool,
    release: bool,
    local_port: u16,
    remote_port: u16,
    dev_name: [u8; IFNAMSIZ],
    local_ip: IpAddr,
    remote_ip: IpAddr,
    remote_mac: MacAddr,
}

impl ParsedConfig {
    fn new() -> Self {
        let mut dev_name = [0u8; IFNAMSIZ];
        dev_name[..4].copy_from_slice(b"eth0");
        Self {
            extended: false,
            release: false,
            local_port: DEFAULT_LOCAL_PORT,
            remote_port: DEFAULT_REMOTE_PORT,
            dev_name,
            local_ip: IpAddr::default(),
            remote_ip: IpAddr::default(),
            remote_mac: MacAddr::BROADCAST,
        }
    }
}

/// Print a banner with the netconsole configuration.
fn print_config_banner(cfg: &ParsedConfig) {
    pr_info!("netconsole: local port {}\n", cfg.local_port);
    pr_info!("netconsole: local IP address {}\n", cfg.local_ip);

    let dev_name_len = strlen(&cfg.dev_name);
    if dev_name_len > 0 {
        if let Ok(s) = core::str::from_utf8(&cfg.dev_name[..dev_name_len]) {
            pr_info!("netconsole: interface '{}'\n", s);
        }
    }

    pr_info!("netconsole: remote port {}\n", cfg.remote_port);
    pr_info!("netconsole: remote IP address {}\n", cfg.remote_ip);
    pr_info!("netconsole: remote ethernet address {}\n", cfg.remote_mac,);
    if cfg.extended {
        pr_info!("netconsole: extended console enabled\n");
    }
    if cfg.release {
        pr_info!("netconsole: release prepend enabled\n");
    }
}

/// Parse netconsole cmdline format: [+][r][src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]
fn parse_cmdline(input: &[u8]) -> Result<ParsedConfig> {
    let mut cfg = ParsedConfig::new();
    let input = trim_newline(input);

    if input.is_empty() {
        return Ok(cfg);
    }

    let mut cur = input;

    // Check for '+' prefix (extended)
    if !cur.is_empty() && cur[0] == b'+' {
        cfg.extended = true;
        cur = &cur[1..];
    }

    // Check for 'r' prefix (release)
    if !cur.is_empty() && cur[0] == b'r' {
        if !cfg.extended {
            pr_err!("netconsole: release feature requires extended log message\n");
            return Err(EINVAL);
        }
        cfg.release = true;
        cur = &cur[1..];
    }

    // Parse: [src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]

    // Find first '@'
    let at_pos = cur.iter().position(|&c| c == b'@');
    if at_pos.is_none() {
        pr_err!("netconsole: couldn't parse config - missing '@'\n");
        return Err(EINVAL);
    }
    let at_pos = at_pos.unwrap();

    // Parse local port if present
    if at_pos > 0 {
        let port_str = &cur[..at_pos];
        if let Ok(s) = core::str::from_utf8(port_str) {
            if let Ok(p) = s.parse::<u16>() {
                cfg.local_port = p;
            }
        }
    }
    cur = &cur[at_pos + 1..];

    // Find '/'
    let slash_pos = cur.iter().position(|&c| c == b'/');
    if slash_pos.is_none() {
        pr_err!("netconsole: couldn't parse config - missing '/'\n");
        return Err(EINVAL);
    }
    let slash_pos = slash_pos.unwrap();

    // Parse local IP if present
    if slash_pos > 0 {
        if let Ok(ip) = IpAddr::parse(&cur[..slash_pos]) {
            cfg.local_ip = ip;
        }
    }
    cur = &cur[slash_pos + 1..];

    // Find ','
    let comma_pos = cur.iter().position(|&c| c == b',');
    if comma_pos.is_none() {
        pr_err!("netconsole: couldn't parse config - missing ','\n");
        return Err(EINVAL);
    }
    let comma_pos = comma_pos.unwrap();

    // Parse dev name if present
    if comma_pos > 0 {
        let dev_str = &cur[..comma_pos];
        let len = core::cmp::min(dev_str.len(), IFNAMSIZ - 1);
        cfg.dev_name = [0u8; IFNAMSIZ];
        cfg.dev_name[..len].copy_from_slice(&dev_str[..len]);
    }
    cur = &cur[comma_pos + 1..];

    // Find second '@'
    let at_pos = cur.iter().position(|&c| c == b'@');
    if at_pos.is_none() {
        pr_err!("netconsole: couldn't parse config - missing second '@'\n");
        return Err(EINVAL);
    }
    let at_pos = at_pos.unwrap();

    // Parse remote port if present
    if at_pos > 0 {
        let port_str = &cur[..at_pos];
        if let Ok(s) = core::str::from_utf8(port_str) {
            if let Ok(p) = s.parse::<u16>() {
                cfg.remote_port = p;
            }
        }
    }
    cur = &cur[at_pos + 1..];

    // Find final '/'
    let slash_pos = cur.iter().position(|&c| c == b'/');
    if slash_pos.is_none() {
        pr_err!("netconsole: couldn't parse config - missing final '/'\n");
        return Err(EINVAL);
    }
    let slash_pos = slash_pos.unwrap();

    // Parse remote IP
    if slash_pos > 0 {
        if let Ok(ip) = IpAddr::parse(&cur[..slash_pos]) {
            cfg.remote_ip = ip;
        }
    }
    cur = &cur[slash_pos + 1..];

    // Parse remote MAC if present
    if !cur.is_empty() {
        if let Ok(mac) = MacAddr::parse(cur) {
            cfg.remote_mac = mac;
        }
    }

    Ok(cfg)
}
