//! # License
//!
//! Copyright (C) 2017  Amagicom AB
//!
//! This program is free software: you can redistribute it and/or modify it under the terms of the
//! GNU General Public License as published by the Free Software Foundation, either version 3 of
//! the License, or (at your option) any later version.

#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate mullvad_ipc_client;
extern crate mullvad_types;
extern crate serde;
extern crate talpid_types;

mod cmds;


use std::io;

error_chain! {
    foreign_links {
        Io(io::Error);
        ParseIntError(::std::num::ParseIntError);
    }

    links {
        RpcError(mullvad_ipc_client::Error, mullvad_ipc_client::ErrorKind);
    }
}

quick_main!(run);

fn run() -> Result<()> {
    env_logger::init();

    let commands = cmds::get_commands();

    let app = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .setting(clap::AppSettings::SubcommandRequired)
        .subcommands(commands.values().map(|cmd| cmd.clap_subcommand()));

    let app_matches = app.get_matches();
    let (subcommand_name, subcommand_matches) = app_matches.subcommand();
    if let Some(cmd) = commands.get(subcommand_name) {
        cmd.run(subcommand_matches.expect("No command matched"))
    } else {
        unreachable!("No command matched");
    }
}

pub trait Command {
    fn name(&self) -> &'static str;

    fn clap_subcommand(&self) -> clap::App<'static, 'static>;

    fn run(&self, matches: &clap::ArgMatches) -> Result<()>;
}
