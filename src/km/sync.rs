//! Kernel-mode synchronization primitives

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};

/// kernel spinlock (KSPIN_LOCK)
#[repr(transparent)]
pub struct SpinLockRaw(usize);

impl SpinLockRaw {
    /// create uninitialized spinlock
    pub const fn new() -> Self {
        Self(0)
    }
}

/// RAII spinlock guard
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    old_irql: u8,
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY: we hold the lock and have valid old_irql
        unsafe {
            KeReleaseSpinLock(&self.lock.raw as *const _ as *mut _, self.old_irql);
        }
    }
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: we hold the lock
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: we hold the lock exclusively
        unsafe { &mut *self.lock.data.get() }
    }
}

/// spinlock protecting data T
pub struct SpinLock<T> {
    raw: SpinLockRaw,
    data: UnsafeCell<T>,
}

// SAFETY: SpinLock provides exclusive access through lock()
unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// create new spinlock with data
    pub const fn new(data: T) -> Self {
        Self {
            raw: SpinLockRaw::new(),
            data: UnsafeCell::new(data),
        }
    }

    /// initialize the spinlock (must be called before first use)
    pub fn init(&mut self) {
        // SAFETY: valid spinlock pointer
        unsafe {
            KeInitializeSpinLock(&mut self.raw as *mut _ as *mut _);
        }
    }

    /// acquire spinlock (raises IRQL to DISPATCH_LEVEL)
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let mut old_irql: u8 = 0;
        // SAFETY: valid spinlock pointer
        unsafe {
            KeAcquireSpinLock(&self.raw as *const _ as *mut _, &mut old_irql);
        }
        SpinLockGuard {
            lock: self,
            old_irql,
        }
    }

    /// try to acquire spinlock without blocking
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let mut old_irql: u8 = 0;
        // SAFETY: valid spinlock pointer
        let acquired = unsafe {
            KeTryToAcquireSpinLockAtDpcLevel(&self.raw as *const _ as *mut _)
        };

        if acquired != 0 {
            Some(SpinLockGuard {
                lock: self,
                old_irql,
            })
        } else {
            None
        }
    }

    /// get mutable reference without locking (unsafe)
    ///
    /// # Safety
    /// caller must ensure exclusive access
    pub unsafe fn get_unchecked(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

/// fast mutex (FAST_MUTEX)
#[repr(C)]
pub struct FastMutexRaw {
    count: i32,
    owner: *mut c_void,
    contention: u32,
    event: [u8; 24], // KEVENT
    old_irql: u32,
}

/// RAII fast mutex guard
pub struct FastMutexGuard<'a, T> {
    mutex: &'a FastMutex<T>,
}

impl<'a, T> Drop for FastMutexGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY: we hold the mutex
        unsafe {
            ExReleaseFastMutex(&self.mutex.raw as *const _ as *mut _);
        }
    }
}

impl<'a, T> Deref for FastMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: we hold the mutex
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T> DerefMut for FastMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: we hold the mutex exclusively
        unsafe { &mut *self.mutex.data.get() }
    }
}

/// fast mutex protecting data T (APC level, can't be used at DISPATCH_LEVEL)
pub struct FastMutex<T> {
    raw: FastMutexRaw,
    data: UnsafeCell<T>,
}

// SAFETY: FastMutex provides exclusive access through lock()
unsafe impl<T: Send> Send for FastMutex<T> {}
unsafe impl<T: Send> Sync for FastMutex<T> {}

impl<T> FastMutex<T> {
    /// create new fast mutex (uninitialized)
    pub fn new(data: T) -> Self {
        Self {
            raw: FastMutexRaw {
                count: 1,
                owner: core::ptr::null_mut(),
                contention: 0,
                event: [0; 24],
                old_irql: 0,
            },
            data: UnsafeCell::new(data),
        }
    }

    /// initialize the mutex (must be called before first use)
    pub fn init(&mut self) {
        // SAFETY: valid mutex pointer
        unsafe {
            ExInitializeFastMutex(&mut self.raw as *mut _ as *mut _);
        }
    }

    /// acquire mutex (raises IRQL to APC_LEVEL)
    pub fn lock(&self) -> FastMutexGuard<'_, T> {
        // SAFETY: valid mutex pointer
        unsafe {
            ExAcquireFastMutex(&self.raw as *const _ as *mut _);
        }
        FastMutexGuard { mutex: self }
    }

    /// try to acquire mutex without blocking
    pub fn try_lock(&self) -> Option<FastMutexGuard<'_, T>> {
        // SAFETY: valid mutex pointer
        let acquired = unsafe {
            ExTryToAcquireFastMutex(&self.raw as *const _ as *mut _)
        };

        if acquired != 0 {
            Some(FastMutexGuard { mutex: self })
        } else {
            None
        }
    }
}

/// RAII wrapper for generic locked data
pub struct Guarded<T, L> {
    data: T,
    lock: L,
}

impl<T, L> Guarded<T, L> {
    /// create new guarded data
    pub fn new(data: T, lock: L) -> Self {
        Self { data, lock }
    }
}

/// push lock (EX_PUSH_LOCK) - lightweight reader/writer lock
#[repr(transparent)]
pub struct PushLockRaw(usize);

impl PushLockRaw {
    pub const fn new() -> Self {
        Self(0)
    }
}

/// push lock wrapper
pub struct PushLock<T> {
    raw: PushLockRaw,
    data: UnsafeCell<T>,
}

// SAFETY: PushLock provides synchronized access
unsafe impl<T: Send> Send for PushLock<T> {}
unsafe impl<T: Send + Sync> Sync for PushLock<T> {}

impl<T> PushLock<T> {
    /// create new push lock
    pub const fn new(data: T) -> Self {
        Self {
            raw: PushLockRaw::new(),
            data: UnsafeCell::new(data),
        }
    }

    /// initialize push lock
    pub fn init(&mut self) {
        // SAFETY: valid pointer
        unsafe {
            ExInitializePushLock(&mut self.raw as *mut _ as *mut _);
        }
    }

    /// acquire exclusive (write) lock
    pub fn lock_exclusive(&self) -> PushLockExclusiveGuard<'_, T> {
        // SAFETY: valid pointer
        unsafe {
            ExAcquirePushLockExclusive(&self.raw as *const _ as *mut _);
        }
        PushLockExclusiveGuard { lock: self }
    }

    /// acquire shared (read) lock
    pub fn lock_shared(&self) -> PushLockSharedGuard<'_, T> {
        // SAFETY: valid pointer
        unsafe {
            ExAcquirePushLockShared(&self.raw as *const _ as *mut _);
        }
        PushLockSharedGuard { lock: self }
    }
}

/// exclusive guard for push lock
pub struct PushLockExclusiveGuard<'a, T> {
    lock: &'a PushLock<T>,
}

impl<'a, T> Drop for PushLockExclusiveGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY: we hold the lock
        unsafe {
            ExReleasePushLockExclusive(&self.lock.raw as *const _ as *mut _);
        }
    }
}

impl<'a, T> Deref for PushLockExclusiveGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for PushLockExclusiveGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

/// shared guard for push lock
pub struct PushLockSharedGuard<'a, T> {
    lock: &'a PushLock<T>,
}

impl<'a, T> Drop for PushLockSharedGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY: we hold the lock
        unsafe {
            ExReleasePushLockShared(&self.lock.raw as *const _ as *mut _);
        }
    }
}

impl<'a, T> Deref for PushLockSharedGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

// kernel synchronization functions
extern "system" {
    fn KeInitializeSpinLock(SpinLock: *mut c_void);
    fn KeAcquireSpinLock(SpinLock: *mut c_void, OldIrql: *mut u8);
    fn KeReleaseSpinLock(SpinLock: *mut c_void, NewIrql: u8);
    fn KeTryToAcquireSpinLockAtDpcLevel(SpinLock: *mut c_void) -> u32;

    fn ExInitializeFastMutex(FastMutex: *mut c_void);
    fn ExAcquireFastMutex(FastMutex: *mut c_void);
    fn ExReleaseFastMutex(FastMutex: *mut c_void);
    fn ExTryToAcquireFastMutex(FastMutex: *mut c_void) -> u8;

    fn ExInitializePushLock(PushLock: *mut c_void);
    fn ExAcquirePushLockExclusive(PushLock: *mut c_void);
    fn ExReleasePushLockExclusive(PushLock: *mut c_void);
    fn ExAcquirePushLockShared(PushLock: *mut c_void);
    fn ExReleasePushLockShared(PushLock: *mut c_void);
}
