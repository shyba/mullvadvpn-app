use clap;
use {Command, Result};

use mullvad_ipc_client::DaemonRpcClient;

pub struct Lan;

impl Command for Lan {
    fn name(&self) -> &'static str {
        "lan"
    }

    fn clap_subcommand(&self) -> clap::App<'static, 'static> {
        clap::SubCommand::with_name(self.name())
            .about("Control the allow local network sharing setting")
            .setting(clap::AppSettings::SubcommandRequired)
            .subcommand(
                clap::SubCommand::with_name("set")
                    .about("Change allow LAN setting")
                    .arg(
                        clap::Arg::with_name("policy")
                            .required(true)
                            .possible_values(&["allow", "block"]),
                    ),
            ).subcommand(
                clap::SubCommand::with_name("get")
                    .about("Display the current local network sharing setting"),
            )
    }

    fn run(&self, matches: &clap::ArgMatches) -> Result<()> {
        if let Some(set_matches) = matches.subcommand_matches("set") {
            let allow_lan = value_t_or_exit!(set_matches.value_of("policy"), String);
            self.set(allow_lan == "allow")
        } else if let Some(_matches) = matches.subcommand_matches("get") {
            self.get()
        } else {
            unreachable!("No lan command given");
        }
    }
}

impl Lan {
    fn set(&self, allow_lan: bool) -> Result<()> {
        let mut rpc = DaemonRpcClient::new()?;
        rpc.set_allow_lan(allow_lan)?;
        println!("Changed local network sharing setting");
        Ok(())
    }

    fn get(&self) -> Result<()> {
        let mut rpc = DaemonRpcClient::new()?;
        let allow_lan = rpc.get_allow_lan()?;
        println!(
            "Local network sharing setting: {}",
            if allow_lan { "allow" } else { "block" }
        );
        Ok(())
    }
}
