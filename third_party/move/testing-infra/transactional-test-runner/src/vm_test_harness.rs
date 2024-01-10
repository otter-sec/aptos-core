// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{run_test_impl, CompiledState, MoveTestAdapter},
    tasks::{EmptyCommand, InitCommand, SyntaxChoice, TaskInput},
    vm_test_harness::dumper::{FundAmount, UserAccount},
};
use anyhow::{anyhow, Result};
use clap::Parser;
use move_binary_format::{
    access::ModuleAccess,
    compatibility::Compatibility,
    errors::{Location, VMError, VMResult, PartialVMError},
    file_format::{CompiledScript, FunctionDefinitionIndex},
    CompiledModule,
};
use move_command_line_common::{
    address::ParsedAddress, env::read_bool_env_var, files::verify_and_create_named_address_mapping,
};
use move_compiler::{
    compiled_unit::AnnotatedCompiledUnit,
    shared::{known_attributes::KnownAttribute, Flags, PackagePaths},
    FullyCompiledProgram,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag, TypeTag},
    resolver::MoveResolver,
    value::MoveValue,
};
use move_resource_viewer::MoveValueAnnotator;
use move_stdlib::move_stdlib_named_addresses;
use move_symbol_pool::Symbol;
use move_vm_runtime::{
    config::VMConfig,
    move_vm::MoveVM,
    session::{SerializedReturnValues, Session},
};
use move_vm_test_utils::{gas_schedule::GasStatus, InMemoryStorage};
use once_cell::sync::Lazy;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use self::dumper::RunnableScript;

const STD_ADDR: AccountAddress = AccountAddress::ONE;

struct SimpleVMTestAdapter<'a> {
    compiled_state: CompiledState<'a>,
    storage: InMemoryStorage,
    default_syntax: SyntaxChoice,
    comparison_mode: bool,
    run_config: TestRunConfig,
}

#[cfg(feature = "dumper")]
pub mod dumper {
    use arbitrary::*;
    use dearbitrary::*;
    use move_binary_format::{
        file_format::{CompiledScript, FunctionDefinitionIndex},
        CompiledModule,
    };
    use move_core_types::{
        language_storage::{ModuleId, TypeTag},
        value::MoveValue,
    };
    use sha2::{Digest, Sha256};
    use std::{io::Write, path::Path};

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq)]
    pub struct RunnableScript {
        pub script: CompiledScript,
        pub type_args: Vec<TypeTag>,
        pub args: Vec<MoveValue>,
    }

    impl RunnableScript {
        pub fn store(&self, folder: impl AsRef<Path>) {
            std::fs::create_dir_all(folder.as_ref()).unwrap();
            let d = self.dearbitrary_first();
            let mvarb_data = d.finish();

            let mut hasher = Sha256::new();
            hasher.update(&mvarb_data);
            let hash = hex::encode(hasher.finalize());

            let mut mvarb_file =
                std::fs::File::create(folder.as_ref().join(format!("{hash}.mvscript"))).unwrap();
            mvarb_file.write_all(&mvarb_data).unwrap();
            let mut u = Unstructured::new(&mvarb_data);
            assert_eq!(self, &Self::arbitrary_take_rest(u).unwrap());
        }
    }

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq, Clone)]
    pub enum FundAmount {
        Zero,
        Poor,
        Rich,
    }

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq, Clone)]
    pub struct UserAccount {
        pub is_inited_and_funded: bool,
        pub fund: FundAmount,
    }

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq, Clone)]
    pub enum Authenticator {
        Ed25519 {
            sender: UserAccount,
        },
        MultiAgent {
            sender: UserAccount,
            secondary_signers: Vec<UserAccount>,
        },
        FeePayer {
            sender: UserAccount,
            secondary_signers: Vec<UserAccount>,
            fee_payer: UserAccount,
        },
    }

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq, Clone)]
    pub enum ExecVariant {
        Script {
            script: CompiledScript,
            type_args: Vec<TypeTag>,
            args: Vec<MoveValue>,
        },
        CallFunction {
            module: ModuleId,
            function: FunctionDefinitionIndex,
            type_args: Vec<TypeTag>,
            args: Vec<Vec<u8>>,
        },
    }

    #[derive(Debug, Arbitrary, Dearbitrary, Eq, PartialEq, Clone)]
    pub struct RunnableState {
        pub dep_modules: Vec<CompiledModule>,
        pub exec_variant: ExecVariant,
        pub tx_auth_type: Authenticator,
    }

    impl RunnableState {
        pub fn store(&self, folder: impl AsRef<Path>) {
            std::fs::create_dir_all(folder.as_ref()).unwrap();
            let d = self.dearbitrary_first();
            let mvarb_data = d.finish();

            let mut hasher = Sha256::new();
            hasher.update(&mvarb_data);
            let hash = hex::encode(hasher.finalize());

            let mut mvarb_file =
                std::fs::File::create(folder.as_ref().join(format!("{hash}.mvrs"))).unwrap();
            mvarb_file.write_all(&mvarb_data).unwrap();
            let mut u = Unstructured::new(&mvarb_data);
            assert_eq!(self, &Self::arbitrary_take_rest(u).unwrap());
        }
    }
}

pub fn view_resource_in_move_storage(
    storage: &impl MoveResolver<PartialVMError>,
    address: AccountAddress,
    module: &ModuleId,
    resource: &IdentStr,
    type_args: Vec<TypeTag>,
) -> Result<String> {
    let tag = StructTag {
        address: *module.address(),
        module: module.name().to_owned(),
        name: resource.to_owned(),
        type_params: type_args,
    };
    // TODO
    match storage.get_resource(&address, &tag).unwrap() {
        None => Ok("[No Resource Exists]".to_owned()),
        Some(data) => {
            let annotated = MoveValueAnnotator::new(storage).view_resource(&tag, &data)?;
            Ok(format!("{}", annotated))
        },
    }
}

#[derive(Debug, Parser)]
pub struct AdapterPublishArgs {
    #[clap(long)]
    /// is skip the struct_and_pub_function_linking compatibility check
    pub skip_check_struct_and_pub_function_linking: bool,
    #[clap(long)]
    /// is skip the struct_layout compatibility check
    pub skip_check_struct_layout: bool,
    #[clap(long)]
    /// is skip the check friend link, if true, treat `friend` as `private`
    pub skip_check_friend_linking: bool,
    /// print more complete information for VMErrors on publish
    #[clap(long)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct AdapterExecuteArgs {
    #[clap(long)]
    pub check_runtime_types: bool,
    /// print more complete information for VMErrors on run
    #[clap(long)]
    pub verbose: bool,
}

fn move_test_debug() -> bool {
    static MOVE_TEST_DEBUG: Lazy<bool> = Lazy::new(|| read_bool_env_var("MOVE_TEST_DEBUG"));
    *MOVE_TEST_DEBUG
}

impl<'a> MoveTestAdapter<'a> for SimpleVMTestAdapter<'a> {
    type ExtraInitArgs = EmptyCommand;
    type ExtraPublishArgs = AdapterPublishArgs;
    type ExtraRunArgs = AdapterExecuteArgs;
    type ExtraValueArgs = ();
    type Subcommand = EmptyCommand;

    fn compiled_state(&mut self) -> &mut CompiledState<'a> {
        &mut self.compiled_state
    }

    fn default_syntax(&self) -> SyntaxChoice {
        self.default_syntax
    }

    fn known_attributes(&self) -> &BTreeSet<String> {
        KnownAttribute::get_all_attribute_names()
    }

    fn run_config(&self) -> TestRunConfig {
        self.run_config
    }

    fn init(
        default_syntax: SyntaxChoice,
        comparison_mode: bool,
        run_config: TestRunConfig,
        pre_compiled_deps: Option<&'a FullyCompiledProgram>,
        task_opt: Option<TaskInput<(InitCommand, EmptyCommand)>>,
    ) -> (Self, Option<String>) {
        let additional_mapping = match task_opt.map(|t| t.command) {
            Some((InitCommand { named_addresses }, _)) => {
                verify_and_create_named_address_mapping(named_addresses).unwrap()
            },
            None => BTreeMap::new(),
        };

        let mut named_address_mapping = move_stdlib_named_addresses();
        for (name, addr) in additional_mapping {
            if named_address_mapping.contains_key(&name) {
                panic!(
                    "Invalid init. The named address '{}' is reserved by the move-stdlib",
                    name
                )
            }
            named_address_mapping.insert(name, addr);
        }
        let mut adapter = Self {
            compiled_state: CompiledState::new(named_address_mapping, pre_compiled_deps, None),
            default_syntax,
            comparison_mode,
            run_config,
            storage: InMemoryStorage::new(),
        };

        adapter
            .perform_session_action(
                None,
                |session, gas_status| {
                    for module in &*MOVE_STDLIB_COMPILED {
                        let mut module_bytes = vec![];
                        module.serialize(&mut module_bytes).unwrap();

                        let id = module.self_id();
                        let sender = *id.address();
                        session
                            .publish_module(module_bytes, sender, gas_status)
                            .unwrap();
                    }
                    Ok(())
                },
                VMConfig::production(),
            )
            .unwrap();
        let mut addr_to_name_mapping = BTreeMap::new();
        for (name, addr) in move_stdlib_named_addresses() {
            let prev = addr_to_name_mapping.insert(addr, Symbol::from(name));
            assert!(prev.is_none());
        }
        for module in MOVE_STDLIB_COMPILED
            .iter()
            .filter(|module| !adapter.compiled_state.is_precompiled_dep(&module.self_id()))
            .collect::<Vec<_>>()
        {
            adapter
                .compiled_state
                .add_and_generate_interface_file(module.clone());
        }
        (adapter, None)
    }

    fn publish_module(
        &mut self,
        module: CompiledModule,
        _named_addr_opt: Option<Identifier>,
        gas_budget: Option<u64>,
        extra_args: Self::ExtraPublishArgs,
    ) -> Result<(Option<String>, CompiledModule)> {
        let mut module_bytes = vec![];
        module.serialize(&mut module_bytes)?;
        #[cfg(feature = "dumper")]
        {
            // use arbitrary::*;
            // use dearbitrary::*;
            // use sha2::{Digest, Sha256};
            // use std::io::Write;
            //
            // let mut hasher = Sha256::new();
            // hasher.update(&module_bytes);
            // let hash = hex::encode(hasher.finalize());
            //
            // let gen_folder = Path::new("./seed_mv");
            // std::fs::create_dir_all(gen_folder).unwrap();
            // let mut mv_file = std::fs::File::create(gen_folder.join(format!("{hash}.mv"))).unwrap();
            // mv_file.write_all(&module_bytes).unwrap();
            //
            // let gen_arb_folder = Path::new("./seed_mvarb");
            // std::fs::create_dir_all(gen_arb_folder).unwrap();
            // let mut d = Dearbitrator::new();
            // module.dearbitrary(&mut d);
            // let mvarb_data = d.finish();
            // let mut mvarb_file =
            //     std::fs::File::create(gen_arb_folder.join(format!("{hash}.mvarb"))).unwrap();
            // mvarb_file.write_all(&mvarb_data).unwrap();
            // let mut u = Unstructured::new(&mvarb_data);
            // assert_eq!(module, CompiledModule::arbitrary(&mut u).unwrap());
        }

        let id = module.self_id();
        let sender = *id.address();
        let verbose = extra_args.verbose;
        match self.perform_session_action(
            gas_budget,
            |session, gas_status| {
                let compat = Compatibility::new(
                    !extra_args.skip_check_struct_and_pub_function_linking,
                    !extra_args.skip_check_struct_layout,
                    !extra_args.skip_check_friend_linking,
                );

                session.publish_module_bundle_with_compat_config(
                    vec![module_bytes],
                    sender,
                    gas_status,
                    compat,
                )
            },
            VMConfig::production(),
        ) {
            Ok(()) => Ok((None, module)),
            Err(vm_error) => Err(anyhow!(
                "Unable to publish module '{}'. Got VMError: {}",
                module.self_id(),
                vm_error.format_test_output(
                    move_test_debug() || verbose,
                    !move_test_debug() && self.comparison_mode
                )
            )),
        }
    }

    fn execute_script(
        &mut self,
        script: CompiledScript,
        type_args: Vec<TypeTag>,
        signers: Vec<ParsedAddress>,
        txn_args: Vec<MoveValue>,
        gas_budget: Option<u64>,
        extra_args: Self::ExtraRunArgs,
    ) -> Result<(Option<String>, SerializedReturnValues)> {
        let signers: Vec<_> = signers
            .into_iter()
            .map(|addr| self.compiled_state().resolve_address(&addr))
            .collect();

        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;

        let args = txn_args
            .iter()
            .map(|arg| arg.simple_serialize().unwrap())
            .collect::<Vec<_>>();
        // TODO rethink testing signer args
        let args: Vec<Vec<u8>> = signers
            .iter()
            .map(|a| MoveValue::Signer(*a).simple_serialize().unwrap())
            .chain(args)
            .collect();

        #[cfg(feature = "dumper")]
        {
            let rs = dumper::RunnableState {
                dep_modules: self
                    .compiled_state
                    .dep_modules()
                    .cloned()
                    .filter(|m| !self.compiled_state.is_precompiled_dep(&m.self_id()))
                    .collect(),
                exec_variant: dumper::ExecVariant::Script {
                    script: script.clone(),
                    type_args: type_args.clone(),
                    args: txn_args.clone(),
                },
                tx_auth_type: dumper::Authenticator::Ed25519 {
                    sender: UserAccount {
                        is_inited_and_funded: true,
                        fund: FundAmount::Rich,
                    },
                },
            };
            rs.store(Path::new("./seeds_mvrs"));
            let rs = RunnableScript {
                script: script.clone(),
                type_args: type_args.clone(),
                args: txn_args.clone(),
            };
            rs.store(Path::new("./seeds_script"));
        }

        let verbose = extra_args.verbose;
        let serialized_return_values = self
            .perform_session_action(
                gas_budget,
                |session, gas_status| {
                    session.execute_script(script_bytes, type_args, args, gas_status)
                },
                VMConfig::from(extra_args),
            )
            .map_err(|vm_error| {
                anyhow!(
                    "Script execution failed with VMError: {}",
                    vm_error.format_test_output(
                        move_test_debug() || verbose,
                        !move_test_debug() && self.comparison_mode
                    )
                )
            })?;
        Ok((None, serialized_return_values))
    }

    fn call_function(
        &mut self,
        module: &ModuleId,
        function: &IdentStr,
        type_args: Vec<TypeTag>,
        signers: Vec<ParsedAddress>,
        txn_args: Vec<MoveValue>,
        gas_budget: Option<u64>,
        extra_args: Self::ExtraRunArgs,
    ) -> Result<(Option<String>, SerializedReturnValues)> {
        let signers: Vec<_> = signers
            .into_iter()
            .map(|addr| self.compiled_state().resolve_address(&addr))
            .collect();

        let args = txn_args
            .iter()
            .map(|arg| arg.simple_serialize().unwrap())
            .collect::<Vec<_>>();
        // TODO rethink testing signer args
        let args: Vec<Vec<u8>> = signers
            .iter()
            .map(|a| MoveValue::Signer(*a).simple_serialize().unwrap())
            .chain(args)
            .collect();

        #[cfg(feature = "dumper")]
        {
            if let Some(mdl) = self
                .compiled_state
                .dep_modules()
                .find(|cm| &cm.self_id() == module)
            {
                if let Some((fdi, _)) = mdl.function_defs().iter().enumerate().find(|(_, fd)| {
                    let fh = mdl.function_handle_at(fd.function);
                    let id = mdl.identifier_at(fh.name);
                    id == function
                }) {
                    let rs = dumper::RunnableState {
                        dep_modules: self
                            .compiled_state
                            .dep_modules()
                            .cloned()
                            .filter(|m| !self.compiled_state.is_precompiled_dep(&m.self_id()))
                            .collect(),
                        exec_variant: dumper::ExecVariant::CallFunction {
                            module: module.clone(),
                            function: FunctionDefinitionIndex(fdi as u16),
                            type_args: type_args.clone(),
                            args: args.clone(),
                        },
                        tx_auth_type: dumper::Authenticator::Ed25519 {
                            sender: UserAccount {
                                is_inited_and_funded: true,
                                fund: FundAmount::Rich,
                            },
                        },
                    };
                    rs.store(Path::new("./seeds_mvrs"));
                }
            }
        }

        let verbose = extra_args.verbose;
        let serialized_return_values = self
            .perform_session_action(
                gas_budget,
                |session, gas_status| {
                    session.execute_function_bypass_visibility(
                        module, function, type_args, args, gas_status,
                    )
                },
                VMConfig::from(extra_args),
            )
            .map_err(|vm_error| {
                anyhow!(
                    "Function execution failed with VMError: {}",
                    vm_error.format_test_output(
                        move_test_debug() || verbose,
                        !move_test_debug() && self.comparison_mode
                    )
                )
            })?;
        Ok((None, serialized_return_values))
    }

    fn view_data(
        &mut self,
        address: AccountAddress,
        module: &ModuleId,
        resource: &IdentStr,
        type_args: Vec<TypeTag>,
    ) -> Result<String> {
        view_resource_in_move_storage(&self.storage, address, module, resource, type_args)
    }

    fn handle_subcommand(&mut self, _: TaskInput<Self::Subcommand>) -> Result<Option<String>> {
        unreachable!()
    }
}

impl<'a> SimpleVMTestAdapter<'a> {
    fn perform_session_action<Ret>(
        &mut self,
        gas_budget: Option<u64>,
        f: impl FnOnce(&mut Session, &mut GasStatus) -> VMResult<Ret>,
        vm_config: VMConfig,
    ) -> VMResult<Ret> {
        // start session
        let vm = MoveVM::new_with_config(
            move_stdlib::natives::all_natives(
                STD_ADDR,
                // TODO: come up with a suitable gas schedule
                move_stdlib::natives::GasParameters::zeros(),
            ),
            vm_config,
        )
        .unwrap();
        let (mut session, mut gas_status) = {
            let gas_status = move_cli::sandbox::utils::get_gas_status(
                &move_vm_test_utils::gas_schedule::INITIAL_COST_SCHEDULE,
                gas_budget,
            )
            .unwrap();
            let session = vm.new_session(&self.storage);
            (session, gas_status)
        };

        // perform op
        let res = f(&mut session, &mut gas_status)?;

        // save changeset
        let changeset = session.finish()?;
        self.storage.apply(changeset).unwrap();
        Ok(res)
    }
}

static PRECOMPILED_MOVE_STDLIB: Lazy<FullyCompiledProgram> = Lazy::new(|| {
    let program_res = move_compiler::construct_pre_compiled_lib(
        vec![PackagePaths {
            name: None,
            paths: move_stdlib::move_stdlib_files(),
            named_address_map: move_stdlib::move_stdlib_named_addresses(),
        }],
        None,
        Flags::empty().set_skip_attribute_checks(true), // no point in checking.
        KnownAttribute::get_all_attribute_names(),
    )
    .unwrap();
    match program_res {
        Ok(stdlib) => stdlib,
        Err((files, errors)) => {
            eprintln!("!!!Standard library failed to compile!!!");
            move_compiler::diagnostics::report_diagnostics(&files, errors)
        },
    }
});

static MOVE_STDLIB_COMPILED: Lazy<Vec<CompiledModule>> = Lazy::new(|| {
    let (files, units_res) = move_compiler::Compiler::from_files(
        move_stdlib::move_stdlib_files(),
        vec![],
        move_stdlib::move_stdlib_named_addresses(),
        Flags::empty().set_skip_attribute_checks(true), // no point in checking here.
        KnownAttribute::get_all_attribute_names(),
    )
    .build()
    .unwrap();
    match units_res {
        Err(diags) => {
            eprintln!("!!!Standard library failed to compile!!!");
            move_compiler::diagnostics::report_diagnostics(&files, diags)
        },
        Ok((_, warnings)) if !warnings.is_empty() => {
            eprintln!("!!!Standard library failed to compile!!!");
            move_compiler::diagnostics::report_diagnostics(&files, warnings)
        },
        Ok((units, _warnings)) => units
            .into_iter()
            .filter_map(|m| match m {
                AnnotatedCompiledUnit::Module(annot_module) => {
                    Some(annot_module.named_module.module)
                },
                AnnotatedCompiledUnit::Script(_) => None,
            })
            .collect(),
    }
});

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub enum TestRunConfig {
    CompilerV1,
    CompilerV2,
    ComparisonV1V2,
}

pub fn run_test(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    run_test_with_config(TestRunConfig::CompilerV1, path)
}

pub fn run_test_with_config(
    config: TestRunConfig,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    run_test_impl::<SimpleVMTestAdapter>(config, path, Some(&*PRECOMPILED_MOVE_STDLIB))
}

impl From<AdapterExecuteArgs> for VMConfig {
    fn from(arg: AdapterExecuteArgs) -> VMConfig {
        VMConfig {
            paranoid_type_checks: arg.check_runtime_types,
            ..Self::production()
        }
    }
}
