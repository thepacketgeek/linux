// SPDX-License-Identifier: GPL-2.0

//! Rust minimal sample.
//!
//! This is a sample module written in Rust. It is intended to be a minimal
//! example of how to write a module in Rust. It does not do anything useful,
//! except print a message when it is loaded and unloaded.
//!
//! It provides examples of how to receive module parameters, which can be provided
//! by the user when the module is loaded:
//!
//! ```
//! insmod /lib/modules/$(uname -r)/kernel/samples/rust/rust_minimal.ko test_int=2 test_str=world
//! ```
//!
//! or via kernel cmdline with module dotted notation (when built-in and not built as a module):
//!
//! ```
//! ... rust_minimal.test_int=2 rust_minimal.test_str=world ...
//! ```

use kernel::prelude::*;

module! {
    type: RustMinimal,
    name: "rust_minimal",
    authors: ["Rust for Linux Contributors"],
    description: "Rust minimal sample",
    license: "GPL",
    params: {
        test_int: i64 {
            default: 1,
            description: "This parameter has a default of 1",
        },
        test_str: string {
            default: "hello",
            description: "This parameter has a default of hello",
        }
    },
}

struct RustMinimal {
    numbers: KVec<i32>,
}

impl kernel::Module for RustMinimal {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust minimal sample (init)\n");
        pr_info!("Am I built-in? {}\n", !cfg!(MODULE));
        pr_info!("test_int: {}\n", *module_parameters::test_int.value());
        pr_info!(
            "test_str: {}\n",
            module_parameters::test_str
                .value()
                .as_cstr()
                .expect("test_str has a default value")
        );

        let mut numbers = KVec::new();
        numbers.push(72, GFP_KERNEL)?;
        numbers.push(108, GFP_KERNEL)?;
        numbers.push(200, GFP_KERNEL)?;

        Ok(RustMinimal { numbers })
    }
}

impl Drop for RustMinimal {
    fn drop(&mut self) {
        pr_info!("My numbers are {:?}\n", self.numbers);
        pr_info!("Rust minimal sample (exit)\n");
    }
}
