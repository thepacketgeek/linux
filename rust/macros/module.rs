// SPDX-License-Identifier: GPL-2.0

use std::ffi::CString;

use proc_macro2::{
    Literal,
    TokenStream, //
};
use quote::{
    format_ident,
    quote,
    ToTokens, //
};
use syn::{
    braced,
    bracketed,
    ext::IdentExt,
    parse::{
        Parse,
        ParseStream, //
    },
    parse_quote,
    punctuated::Punctuated,
    Error,
    Expr,
    Ident,
    LitStr,
    Path,
    Result,
    Token,
    Type, //
};

use crate::helpers::*;

struct ModInfoBuilder<'a> {
    module: &'a str,
    counter: usize,
    ts: TokenStream,
    param_ts: TokenStream,
    setup_ts: TokenStream,
}

impl<'a> ModInfoBuilder<'a> {
    fn new(module: &'a str) -> Self {
        ModInfoBuilder {
            module,
            counter: 0,
            ts: TokenStream::new(),
            param_ts: TokenStream::new(),
            setup_ts: TokenStream::new(),
        }
    }

    fn emit_base(&mut self, field: &str, content: &str, builtin: bool, param: bool) {
        let string = if builtin {
            // Built-in modules prefix their modinfo strings by `module.`.
            format!(
                "{module}.{field}={content}\0",
                module = self.module,
                field = field,
                content = content
            )
        } else {
            // Loadable modules' modinfo strings go as-is.
            format!("{field}={content}\0")
        };
        let length = string.len();
        let string = Literal::byte_string(string.as_bytes());
        let cfg = if builtin {
            quote!(#[cfg(not(MODULE))])
        } else {
            quote!(#[cfg(MODULE)])
        };

        let counter = format_ident!(
            "__{module}_{counter}",
            module = self.module.to_uppercase(),
            counter = self.counter
        );
        let item = quote! {
            #cfg
            #[cfg_attr(not(target_os = "macos"), link_section = ".modinfo")]
            #[used(compiler)]
            pub static #counter: [u8; #length] = *#string;
        };

        if param {
            self.param_ts.extend(item);
        } else {
            self.ts.extend(item);
        }

        self.counter += 1;
    }

    fn emit_only_builtin(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, true, param)
    }

    fn emit_only_loadable(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, false, param)
    }

    fn emit(&mut self, field: &str, content: &str) {
        self.emit_internal(field, content, false);
    }

    fn emit_internal(&mut self, field: &str, content: &str, param: bool) {
        self.emit_only_builtin(field, content, param);
        self.emit_only_loadable(field, content, param);
    }

    fn emit_param(&mut self, field: &str, param: &str, content: &str) {
        let content = format!("{param}:{content}", param = param, content = content);
        self.emit_internal(field, &content, true);
    }

    fn emit_params(&mut self, info: &ModuleInfo) {
        let Some(params) = &info.params else {
            return;
        };

        for param in params {
            let param_name_str = param.name.to_string();
            let param_type_str = param.ptype.to_token_stream().to_string();
            // Clean up the type string for modinfo (remove spaces around ::)
            let param_type_clean = param_type_str.replace(" ", "");

            let ops = param_ops_path(&param_type_str);

            // Note: The spelling of these fields is dictated by the user space
            // tool `modinfo`.
            self.emit_param("parmtype", &param_name_str, &param_type_clean);
            self.emit_param("parm", &param_name_str, &param.description.value());

            let static_name = format_ident!("__{}_{}_struct", self.module, param.name);
            let param_name_cstr =
                CString::new(param_name_str).expect("name contains NUL-terminator");
            let param_name_cstr_with_module =
                CString::new(format!("{}.{}", self.module, param.name))
                    .expect("name contains NUL-terminator");

            let param_name = &param.name;
            let param_default = &param.default;

            // `string` is a shorthand for `StringParam` in the macro — resolve to
            // the real type for code generation.
            let is_str_param = param_type_str == "string";
            let actual_type: Type = if is_str_param {
                parse_quote!(::kernel::module_param::StringParam)
            } else {
                param.ptype.clone()
            };

            // For `string` params the default is always a string literal which
            // gets wrapped with StringParam::from_c_str(kernel::c_str!(...)).
            let default_expr = if is_str_param {
                quote! {
                    ::kernel::module_param::StringParam::from_c_str(::kernel::c_str!(#param_default))
                }
            } else {
                quote!(#param_default)
            };

            self.param_ts.extend(quote! {
                #[allow(non_upper_case_globals)]
                pub(crate) static #param_name:
                    ::kernel::module_param::ModuleParamAccess<#actual_type> =
                        ::kernel::module_param::ModuleParamAccess::new(#default_expr);

                const _: () = {
                    #[allow(non_upper_case_globals)]
                    #[link_section = "__param"]
                    #[used(compiler)]
                    static #static_name:
                        ::kernel::module_param::KernelParam =
                        ::kernel::module_param::KernelParam::new(
                            ::kernel::bindings::kernel_param {
                                name: kernel::str::as_char_ptr_in_const_context(
                                    if ::core::cfg!(MODULE) {
                                        #param_name_cstr
                                    } else {
                                        #param_name_cstr_with_module
                                    }
                                ),
                                // SAFETY: `__this_module` is constructed by the kernel at load
                                // time and will not be freed until the module is unloaded.
                                #[cfg(MODULE)]
                                mod_: unsafe {
                                    core::ptr::from_ref(&::kernel::bindings::__this_module)
                                        .cast_mut()
                                },
                                #[cfg(not(MODULE))]
                                mod_: ::core::ptr::null_mut(),
                                ops: core::ptr::from_ref(&#ops),
                                perm: 0, // Will not appear in sysfs
                                level: -1,
                                flags: 0,
                                __bindgen_anon_1: ::kernel::bindings::kernel_param__bindgen_ty_1 {
                                    arg: #param_name.as_void_ptr()
                                },
                            }
                        );
                };
            });
        }
    }

    fn emit_setup(&mut self, info: &ModuleInfo) {
        let Some(params) = &info.params else {
            return;
        };

        for param in params {
            let Some(early_param) = &param.early_param else {
                continue;
            };

            let setup_str_value = early_param.value();
            let param_name = &param.name;

            // Resolve `string` shorthand to the real `StringParam` type.
            let param_type_str = param.ptype.to_token_stream().to_string();
            let actual_type: Type = if param_type_str == "string" {
                parse_quote!(::kernel::module_param::StringParam)
            } else {
                param.ptype.clone()
            };

            // Create identifiers for the generated statics
            let setup_fn_name = format_ident!("__setup_fn_{}", param_name);
            let setup_str_name =
                format_ident!("__SETUP_STR_{}", param_name.to_string().to_uppercase());
            let setup_name = format_ident!("__SETUP_{}", param_name.to_string().to_uppercase());

            // The setup string with null terminator
            let setup_str_bytes = format!("{}\0", setup_str_value);
            let setup_str_len = setup_str_bytes.len();
            let setup_str_lit = Literal::byte_string(setup_str_bytes.as_bytes());

            self.setup_ts.extend(quote! {
                #[cfg(not(MODULE))]
                const _: () = {
                    unsafe extern "C" fn #setup_fn_name(
                        val: *mut ::kernel::ffi::c_char,
                    ) -> ::kernel::ffi::c_int {
                        if val.is_null() {
                            return 0;
                        }
                        // SAFETY: The kernel passes a valid null-terminated string from
                        // `static_command_line`.
                        match unsafe {
                            <#actual_type as ::kernel::module_param::ModuleParam>::from_setup_arg(
                                val as *const _
                            )
                        } {
                            Ok(v) => {
                                if module_parameters::#param_name.set_value(v) { 1 } else { 0 }
                            }
                            Err(_) => 0,
                        }
                    }

                    #[link_section = ".init.rodata"]
                    #[used(compiler)]
                    static #setup_str_name: [u8; #setup_str_len] = *#setup_str_lit;

                    #[link_section = ".init.setup"]
                    #[used(compiler)]
                    static #setup_name: ::kernel::module_param::ObsKernelParam =
                        ::kernel::module_param::ObsKernelParam {
                            str_: #setup_str_name.as_ptr().cast(),
                            setup_func: ::core::option::Option::Some(#setup_fn_name),
                            early: 0,
                        };
                };
            });
        }
    }
}

fn param_ops_path(param_type: &str) -> Path {
    let type_name = param_type.rsplit("::").next().unwrap_or(param_type).trim();

    match type_name {
        "i8" => parse_quote!(::kernel::module_param::PARAM_OPS_I8),
        "u8" => parse_quote!(::kernel::module_param::PARAM_OPS_U8),
        "i16" => parse_quote!(::kernel::module_param::PARAM_OPS_I16),
        "u16" => parse_quote!(::kernel::module_param::PARAM_OPS_U16),
        "i32" => parse_quote!(::kernel::module_param::PARAM_OPS_I32),
        "u32" => parse_quote!(::kernel::module_param::PARAM_OPS_U32),
        "i64" => parse_quote!(::kernel::module_param::PARAM_OPS_I64),
        "u64" => parse_quote!(::kernel::module_param::PARAM_OPS_U64),
        "isize" => parse_quote!(::kernel::module_param::PARAM_OPS_ISIZE),
        "usize" => parse_quote!(::kernel::module_param::PARAM_OPS_USIZE),
        "string" => parse_quote!(::kernel::module_param::PARAM_OPS_STRING),
        t => panic!("Unsupported parameter type {}", t),
    }
}

/// Parse fields that are required to use a specific order.
///
/// As fields must follow a specific order, we *could* just parse fields one by one by peeking.
/// However the error message generated when implementing that way is not very friendly.
///
/// So instead we parse fields in an arbitrary order, but only enforce the ordering after parsing,
/// and if the wrong order is used, the proper order is communicated to the user with error message.
///
/// Usage looks like this:
/// ```ignore
/// parse_ordered_fields! {
///     from input;
///
///     // This will extract "foo: <field>" into a variable named "foo".
///     // The variable will have type `Option<_>`.
///     foo => <expression that parses the field>,
///
///     // If you need the variable name to be different than the key name.
///     // This extracts "baz: <field>" into a variable named "bar".
///     // You might want this if "baz" is a keyword.
///     baz as bar => <expression that parse the field>,
///
///     // You can mark a key as required, and the variable will no longer be `Option`.
///     // foobar will be of type `Expr` instead of `Option<Expr>`.
///     foobar [required] => input.parse::<Expr>()?,
/// }
/// ```
macro_rules! parse_ordered_fields {
    (@gen
        [$input:expr]
        [$([$name:ident; $key:ident; $parser:expr])*]
        [$([$req_name:ident; $req_key:ident])*]
    ) => {
        $(let mut $name = None;)*

        const EXPECTED_KEYS: &[&str] = &[$(stringify!($key),)*];
        const REQUIRED_KEYS: &[&str] = &[$(stringify!($req_key),)*];

        let span = $input.span();
        let mut seen_keys = Vec::new();

        while !$input.is_empty() {
            let key = $input.call(Ident::parse_any)?;

            if seen_keys.contains(&key) {
                Err(Error::new_spanned(
                    &key,
                    format!(r#"duplicated key "{key}". Keys can only be specified once."#),
                ))?
            }

            $input.parse::<Token![:]>()?;

            match &*key.to_string() {
                $(
                    stringify!($key) => $name = Some($parser),
                )*
                _ => {
                    Err(Error::new_spanned(
                        &key,
                        format!(r#"unknown key "{key}". Valid keys are: {EXPECTED_KEYS:?}."#),
                    ))?
                }
            }

            $input.parse::<Token![,]>()?;
            seen_keys.push(key);
        }

        for key in REQUIRED_KEYS {
            if !seen_keys.iter().any(|e| e == key) {
                Err(Error::new(span, format!(r#"missing required key "{key}""#)))?
            }
        }

        let mut ordered_keys: Vec<&str> = Vec::new();
        for key in EXPECTED_KEYS {
            if seen_keys.iter().any(|e| e == key) {
                ordered_keys.push(key);
            }
        }

        if seen_keys != ordered_keys {
            Err(Error::new(
                span,
                format!(r#"keys are not ordered as expected. Order them like: {ordered_keys:?}."#),
            ))?
        }

        $(let $req_name = $req_name.expect("required field");)*
    };

    // Handle required fields.
    (@gen
        [$input:expr] [$($tok:tt)*] [$($req:tt)*]
        $key:ident as $name:ident [required] => $parser:expr,
        $($rest:tt)*
    ) => {
        parse_ordered_fields!(
            @gen [$input] [$($tok)* [$name; $key; $parser]] [$($req)* [$name; $key]] $($rest)*
        )
    };
    (@gen
        [$input:expr] [$($tok:tt)*] [$($req:tt)*]
        $name:ident [required] => $parser:expr,
        $($rest:tt)*
    ) => {
        parse_ordered_fields!(
            @gen [$input] [$($tok)* [$name; $name; $parser]] [$($req)* [$name; $name]] $($rest)*
        )
    };

    // Handle optional fields.
    (@gen
        [$input:expr] [$($tok:tt)*] [$($req:tt)*]
        $key:ident as $name:ident => $parser:expr,
        $($rest:tt)*
    ) => {
        parse_ordered_fields!(
            @gen [$input] [$($tok)* [$name; $key; $parser]] [$($req)*] $($rest)*
        )
    };
    (@gen
        [$input:expr] [$($tok:tt)*] [$($req:tt)*]
        $name:ident => $parser:expr,
        $($rest:tt)*
    ) => {
        parse_ordered_fields!(
            @gen [$input] [$($tok)* [$name; $name; $parser]] [$($req)*] $($rest)*
        )
    };

    (from $input:expr; $($tok:tt)*) => {
        parse_ordered_fields!(@gen [$input] [] [] $($tok)*)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitCallLevel {
    Pure,
    Core,
    PostCore,
    Arch,
    Subsys,
    Fs,
    Device,
    Late,
}

impl InitCallLevel {
    fn section(&self) -> &'static str {
        match self {
            Self::Pure => ".initcall0.init",
            Self::Core => ".initcall1.init",
            Self::PostCore => ".initcall2.init",
            Self::Arch => ".initcall3.init",
            Self::Subsys => ".initcall4.init",
            Self::Fs => ".initcall5.init",
            Self::Device => ".initcall6.init",
            Self::Late => ".initcall7.init",
        }
    }
}

impl Parse for InitCallLevel {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let ident: Ident = input.call(Ident::parse_any)?;
        match ident.to_string().as_str() {
            "pure" => Ok(Self::Pure),
            "core" => Ok(Self::Core),
            "postcore" => Ok(Self::PostCore),
            "arch" => Ok(Self::Arch),
            "subsys" => Ok(Self::Subsys),
            "fs" => Ok(Self::Fs),
            "device" => Ok(Self::Device),
            "late" => Ok(Self::Late),
            _ => Err(Error::new_spanned(
                ident,
                "invalid initcall level. Valid values are: pure, core, postcore, arch, subsys, fs, device, late",
            )),
        }
    }
}

struct Parameter {
    name: Ident,
    ptype: Type,
    default: Expr,
    description: LitStr,
    early_param: Option<LitStr>,
}

impl Parse for Parameter {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![:]>()?;
        let ptype: Type = input.parse()?;

        let fields;
        braced!(fields in input);

        parse_ordered_fields! {
            from fields;
            default [required] => fields.parse()?,
            description [required] => fields.parse()?,
            early_param => fields.parse()?,
        }

        Ok(Self {
            name,
            ptype,
            default,
            description,
            early_param,
        })
    }
}

pub(crate) struct ModuleInfo {
    type_: Type,
    license: AsciiLitStr,
    name: AsciiLitStr,
    authors: Option<Punctuated<AsciiLitStr, Token![,]>>,
    description: Option<LitStr>,
    alias: Option<Punctuated<AsciiLitStr, Token![,]>>,
    firmware: Option<Punctuated<AsciiLitStr, Token![,]>>,
    imports_ns: Option<Punctuated<AsciiLitStr, Token![,]>>,
    params: Option<Punctuated<Parameter, Token![,]>>,
    initcall: Option<InitCallLevel>,
}

impl Parse for ModuleInfo {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        parse_ordered_fields!(
            from input;
            type as type_ [required] => input.parse()?,
            name [required] => input.parse()?,
            authors => {
                let list;
                bracketed!(list in input);
                Punctuated::parse_terminated(&list)?
            },
            description => input.parse()?,
            license [required] => input.parse()?,
            alias => {
                let list;
                bracketed!(list in input);
                Punctuated::parse_terminated(&list)?
            },
            firmware => {
                let list;
                bracketed!(list in input);
                Punctuated::parse_terminated(&list)?
            },
            imports_ns => {
                let list;
                bracketed!(list in input);
                Punctuated::parse_terminated(&list)?
            },
            params => {
                let list;
                braced!(list in input);
                Punctuated::parse_terminated(&list)?
            },
            initcall => input.parse()?,
        );

        Ok(ModuleInfo {
            type_,
            license,
            name,
            authors,
            description,
            alias,
            firmware,
            imports_ns,
            params,
            initcall,
        })
    }
}

pub(crate) fn module(info: ModuleInfo) -> Result<TokenStream> {
    let ModuleInfo {
        type_,
        license,
        name,
        authors,
        description,
        alias,
        firmware,
        imports_ns,
        params: _,
        initcall,
    } = &info;

    // Rust does not allow hyphens in identifiers, use underscore instead.
    let ident = name.value().replace('-', "_");
    let mut modinfo = ModInfoBuilder::new(ident.as_ref());
    if let Some(authors) = authors {
        for author in authors {
            modinfo.emit("author", &author.value());
        }
    }
    if let Some(description) = description {
        modinfo.emit("description", &description.value());
    }
    modinfo.emit("license", &license.value());
    if let Some(aliases) = alias {
        for alias in aliases {
            modinfo.emit("alias", &alias.value());
        }
    }
    if let Some(firmware) = firmware {
        for fw in firmware {
            modinfo.emit("firmware", &fw.value());
        }
    }
    if let Some(imports) = imports_ns {
        for ns in imports {
            modinfo.emit("import_ns", &ns.value());
        }
    }

    // Built-in modules also export the `file` modinfo string.
    let file =
        std::env::var("RUST_MODFILE").expect("Unable to fetch RUST_MODFILE environmental variable");
    modinfo.emit_only_builtin("file", &file, false);

    modinfo.emit_params(&info);
    modinfo.emit_setup(&info);

    let modinfo_ts = modinfo.ts;
    let params_ts = modinfo.param_ts;
    let setup_ts = modinfo.setup_ts;

    let ident_init = format_ident!("__{ident}_init");
    let ident_exit = format_ident!("__{ident}_exit");
    let ident_initcall = format_ident!("__{ident}_initcall");
    let initcall_section = initcall
        .as_ref()
        .unwrap_or(&InitCallLevel::Device)
        .section();

    let global_asm = format!(
        r#".section "{initcall_section}", "a"
        __{ident}_initcall:
            .long   __{ident}_init - .
            .previous
        "#
    );

    let name_cstr = CString::new(name.value()).expect("name contains NUL-terminator");

    Ok(quote! {
        /// The module name.
        ///
        /// Used by the printing macros, e.g. [`info!`].
        const __LOG_PREFIX: &[u8] = #name_cstr.to_bytes_with_nul();

        // SAFETY: `__this_module` is constructed by the kernel at load time and will not be
        // freed until the module is unloaded.
        #[cfg(MODULE)]
        static THIS_MODULE: ::kernel::ThisModule = unsafe {
            extern "C" {
                static __this_module: ::kernel::types::Opaque<::kernel::bindings::module>;
            };

            ::kernel::ThisModule::from_ptr(__this_module.get())
        };

        #[cfg(not(MODULE))]
        static THIS_MODULE: ::kernel::ThisModule = unsafe {
            ::kernel::ThisModule::from_ptr(::core::ptr::null_mut())
        };

        /// The `LocalModule` type is the type of the module created by `module!`,
        /// `module_pci_driver!`, `module_platform_driver!`, etc.
        type LocalModule = #type_;

        impl ::kernel::ModuleMetadata for #type_ {
            const NAME: &'static ::kernel::str::CStr = #name_cstr;
        }

        // Double nested modules, since then nobody can access the public items inside.
        #[doc(hidden)]
        mod __module_init {
            mod __module_init {
                use pin_init::PinInit;

                /// The "Rust loadable module" mark.
                //
                // This may be best done another way later on, e.g. as a new modinfo
                // key or a new section. For the moment, keep it simple.
                #[cfg(MODULE)]
                #[used(compiler)]
                static __IS_RUST_MODULE: () = ();

                static mut __MOD: ::core::mem::MaybeUninit<super::super::LocalModule> =
                    ::core::mem::MaybeUninit::uninit();

                // Loadable modules need to export the `{init,cleanup}_module` identifiers.
                /// # Safety
                ///
                /// This function must not be called after module initialization, because it may be
                /// freed after that completes.
                #[cfg(MODULE)]
                #[no_mangle]
                #[link_section = ".init.text"]
                pub unsafe extern "C" fn init_module() -> ::kernel::ffi::c_int {
                    // SAFETY: This function is inaccessible to the outside due to the double
                    // module wrapping it. It is called exactly once by the C side via its
                    // unique name.
                    unsafe { __init() }
                }

                #[cfg(MODULE)]
                #[used(compiler)]
                #[link_section = ".init.data"]
                static __UNIQUE_ID___addressable_init_module: unsafe extern "C" fn() -> i32 =
                    init_module;

                #[cfg(MODULE)]
                #[no_mangle]
                #[link_section = ".exit.text"]
                pub extern "C" fn cleanup_module() {
                    // SAFETY:
                    // - This function is inaccessible to the outside due to the double
                    //   module wrapping it. It is called exactly once by the C side via its
                    //   unique name,
                    // - furthermore it is only called after `init_module` has returned `0`
                    //   (which delegates to `__init`).
                    unsafe { __exit() }
                }

                #[cfg(MODULE)]
                #[used(compiler)]
                #[link_section = ".exit.data"]
                static __UNIQUE_ID___addressable_cleanup_module: extern "C" fn() = cleanup_module;

                // Built-in modules are initialized through an initcall pointer
                // and the identifiers need to be unique.
                #[cfg(not(MODULE))]
                #[cfg(not(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS))]
                #[link_section = #initcall_section]
                #[used(compiler)]
                pub static #ident_initcall: extern "C" fn() ->
                    ::kernel::ffi::c_int = #ident_init;

                #[cfg(not(MODULE))]
                #[cfg(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS)]
                ::core::arch::global_asm!(#global_asm);

                #[cfg(not(MODULE))]
                #[no_mangle]
                pub extern "C" fn #ident_init() -> ::kernel::ffi::c_int {
                    // SAFETY: This function is inaccessible to the outside due to the double
                    // module wrapping it. It is called exactly once by the C side via its
                    // placement above in the initcall section.
                    unsafe { __init() }
                }

                #[cfg(not(MODULE))]
                #[no_mangle]
                pub extern "C" fn #ident_exit() {
                    // SAFETY:
                    // - This function is inaccessible to the outside due to the double
                    //   module wrapping it. It is called exactly once by the C side via its
                    //   unique name,
                    // - furthermore it is only called after `#ident_init` has
                    //   returned `0` (which delegates to `__init`).
                    unsafe { __exit() }
                }

                /// # Safety
                ///
                /// This function must only be called once.
                unsafe fn __init() -> ::kernel::ffi::c_int {
                    let initer = <super::super::LocalModule as ::kernel::InPlaceModule>::init(
                        &super::super::THIS_MODULE
                    );
                    // SAFETY: No data race, since `__MOD` can only be accessed by this module
                    // and there only `__init` and `__exit` access it. These functions are only
                    // called once and `__exit` cannot be called before or during `__init`.
                    match unsafe { initer.__pinned_init(__MOD.as_mut_ptr()) } {
                        Ok(m) => 0,
                        Err(e) => e.to_errno(),
                    }
                }

                /// # Safety
                ///
                /// This function must
                /// - only be called once,
                /// - be called after `__init` has been called and returned `0`.
                unsafe fn __exit() {
                    // SAFETY: No data race, since `__MOD` can only be accessed by this module
                    // and there only `__init` and `__exit` access it. These functions are only
                    // called once and `__init` was already called.
                    unsafe {
                        // Invokes `drop()` on `__MOD`, which should be used for cleanup.
                        __MOD.assume_init_drop();
                    }
                }

                #modinfo_ts
            }
        }

        mod module_parameters {
            #params_ts
        }

        #setup_ts
    })
}
