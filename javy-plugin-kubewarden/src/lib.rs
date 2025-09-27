use javy_plugin_api::{
    javy::{quickjs::prelude::Func, Runtime},
    javy_plugin, Config,
};

wit_bindgen::generate!({ world: "kubewarden-javy-plugin-v1", generate_all });

// The call function is imported directly via WIT

fn config() -> Config {
    let mut config = Config::default();
    config.text_encoding(true).javy_stream_io(true);
    config
}

fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime
        .context()
        .with(|ctx| {
            ctx.globals().set(
                "policyAction",
                Func::from(|| {
                    let args = std::env::args().collect::<Vec<String>>();
                    if args.len() != 2 {
                        // TODO: move to Error::UserData when javy upgrades to latest version of rquickjs
                        return Err(javy_plugin_api::javy::quickjs::Error::Unknown);
                    }
                    Ok(args[1].clone())
                }),
            )
        })
        .unwrap();

    runtime
        .context()
        .with(|ctx| {
            ctx.globals().set(
                "__hostCall",
                Func::from(
                    |binding: String,
                     ns: String,
                     op: String,
                     msg: javy_plugin_api::javy::quickjs::Object| {
                        let msg = msg
                            .as_array_buffer()
                            .and_then(|ab| ab.as_bytes())
                            .ok_or(javy_plugin_api::javy::quickjs::Error::Unknown)?; // TODO: move to Error::UserData when javy upgrades to latest version of rquickjs

                        let successful = crate::call(
                            binding.as_ptr() as u32,
                            binding.len() as u32,
                            ns.as_ptr() as u32,
                            ns.len() as u32,
                            op.as_ptr() as u32,
                            op.len() as u32,
                            msg.as_ptr() as u32,
                            msg.len() as u32,
                        );

                        Ok::<bool, javy_plugin_api::javy::quickjs::Error>(successful == 0)
                    },
                ),
            )
        })
        .unwrap();

    runtime
}

struct Component;

// Dynamically linked modules will use `kubewarden-javy-plugin-v1` as the import
// namespace.
javy_plugin!(
    "kubewarden-javy-plugin-v1",
    Component,
    config,
    modify_runtime
);

export!(Component);
