pub mod config {

    use clap::{Arg, Command, ArgAction};
    use crate::application_service::registration::Registration;

    #[derive(Clone, Debug)]
    pub struct Config {
        pub matrix_server: String,
        pub registration: Registration,
        pub lnbits_url: String,
        pub lnbits_bearer_token: String,
        pub lnbits_api_key: String,
        pub database_url: String,
        pub avatar_path: Option<String>,
        pub debug_level: String,
        pub allowed_matrix_servers: Option<Vec<String>>,
    }

    impl Config {
        pub fn new(matrix_server: &str,
                   registration: Registration,
                   lnbits_url: &str,
                   lnbits_bearer_token: &str,
                   lnbits_api_key: &str,
                   database_url: &str,
                   avatar_path: Option<String>,
                   debug_level: &str,
                   allowed_matrix_servers: Option<Vec<String>>) -> Config {
            Config {
                matrix_server: matrix_server.to_string(),
                registration,
                lnbits_url: lnbits_url.to_string(),
                lnbits_bearer_token: lnbits_bearer_token.to_string(),
                lnbits_api_key: lnbits_api_key.to_string(),
                database_url: database_url.to_string(),
                avatar_path,
                debug_level: debug_level.to_string(),
                allowed_matrix_servers
            }
        }
    }

    pub fn config_from_cmd() -> Config {
        let args = wild::args_os();
        let args = argfile::expand_args_from(
            args,
            argfile::parse_fromfile,
            argfile::PREFIX,
        ).unwrap();

        let matches = Command::new("LN-Matrix-Bot")
            .version("0.9.0")
            .author("AE")
            .about("LN-Matrix-Bot")
            .arg(Arg::new("matrix-server")
                .long("matrix-server")
                .required(true)
                .help("Server"))
            .arg(Arg::new("registration-file")
                .long("registration-file")
                .required(true)
                .help("Path to the application service registration YAML"))
            .arg(Arg::new("lnbits-url")
                .long("lnbits-url")
                .required(true)
                .help("lnbits url"))
            .arg(Arg::new("lnbits-bearer-token")
                .long("lnbits-bearer-token")
                .required(true)
                .help("lnbits bearer token"))
            .arg(Arg::new("lnbits-api-key")
                .long("lnbits-api-key")
                .required(true)
                .help("lnbits api key"))
            .arg(Arg::new("database-url")
                .long("database-url")
                .required(true)
                .help("database url"))
            .arg(Arg::new("avatar-path")
                .long("avatar-path")
                .required(false)
                .help("mxc:// URL to set as the bot's avatar"))
            .arg(Arg::new("debug-level")
                .long("debug-level")
                .default_value("Info")
                .required(false)
                .help("debugging level"))
            .arg(Arg::new("allowed-matrix-server")
                .long("allowed-matrix-server")
                .num_args(1)
                .action(ArgAction::Append)
                .required(false)
                .help("Matrix servers allowed to use the bot. Can be repeated"))

            .get_matches_from(args);

        let matrix_server = matches.get_one::<String>("matrix-server").unwrap();

        let registration_file = matches.get_one::<String>("registration-file").unwrap();
        let registration_path = std::path::Path::new(registration_file);
        let registration = Registration::load(registration_path).expect("Could not load registration file");

        let lnbits_url = matches.get_one::<String>("lnbits-url").unwrap();

        let lnbits_bearer_token = matches.get_one::<String>("lnbits-bearer-token").unwrap();
        let lnbits_api_key = matches.get_one::<String>("lnbits-api-key").unwrap();

        let database_url = matches.get_one::<String>("database-url").unwrap();


        let avatar_path = matches
            .get_one::<String>("avatar-path")
            .map(|s| s.to_string());

        let debug_level = matches.get_one::<String>("debug-level").unwrap();

        let allowed_matrix_servers = matches
            .get_many::<String>("allowed-matrix-server")
            .map(|vals| vals.map(|v| v.to_string()).collect::<Vec<String>>());

        Config::new(matrix_server,
                    registration,
                    lnbits_url,
                    lnbits_bearer_token,
                    lnbits_api_key,
                    database_url,
                    avatar_path,
                    debug_level,
                    allowed_matrix_servers)
    }
}
