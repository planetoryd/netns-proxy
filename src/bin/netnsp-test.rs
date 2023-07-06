use nix::sched::{unshare, CloneFlags};

// a tester for netns-proxy
use anyhow::{Context, Result};
use std::io::{self, BufRead};
use std::process::Command;
use tokio::process::Command as TokioCommand;

fn compile_tests() -> String {
    String::from_utf8(
        Command::new("cargo")
            .args(&["test", "--offline", "--no-run"])
            .output()
            .expect("Failed to execute command")
            .stdout,
    )
    .expect("Invalid UTF-8 sequence")
}

fn extract_executable_paths(stdout: &str) -> Vec<String> {
    let mut result = Vec::new();

    for line in stdout.lines() {
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                result.push(line[start + 1..end].to_string());
            }
        }
    }
    let v: Vec<String> = result
        .into_iter()
        .filter(|x| x.starts_with("target/debu"))
        .collect();

    v
}

fn extract_test_names(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.ends_with("test"))
        .filter_map(|line| {
            let at = line.rfind(":");
            if let Some(i) = at {
                let (left, right) = line.split_at(i);
                let s: String = left.to_string();
                Some(s)
            } else {
                None
            }
        })
        .collect()
}

async fn run_test(binary: &str, test: &str) -> Result<()> {
    let mut cmd = TokioCommand::new(&binary);
    cmd.arg(test);

    let output = cmd
        .output()
        .await
        .context(format!("failed to execute test '{}::{}'", binary, test))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout_str);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let stdout = compile_tests();
    let binaries = extract_executable_paths(&stdout);

    for binary in binaries {
        let output = Command::new(&binary)
            .arg("--list")
            .output()
            .expect("Failed to execute command")
            .stdout;

        let output_str = String::from_utf8_lossy(&output);
        println!("{}:\n{}\n", binary, output_str);

        let test_names = extract_test_names(&output_str);

        for test_name in test_names {
            run_test(&binary, &test_name).await?;
        }
    }

    Ok(())
}

fn isolate_selfproc() -> Result<()> {
    // we'll only unshare netns
    // flatpak related things will be tested on system directly. And they must not damage the system.
    unshare(CloneFlags::CLONE_NEWNET)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_executable_paths() {
        let stdout = "\
arning: `netns-proxy` (bin \"netnsp-test\" test) generated 3 warnings (run `cargo fix --bin \"netnsp-test\" --tests` to apply 2 suggestions)
warning: `netns-proxy` (bin \"nsproxy\" test) generated 3 warnings (run `cargo fix --bin \"nsproxy\" --tests` to apply 3 suggestions)
    Finished test [unoptimized + debuginfo] target(s) in 0.08s
  Executable unittests src/lib.rs (target/debug/deps/netns_proxy-0b269e570007cd4d)
  Executable unittests src/bin/netnsp-sub.rs (target/debug/deps/netnsp_sub-b94893ff59ca47ab)
  Executable unittests src/bin/netnsp-test.rs (target/debug/deps/netnsp_test-1432dd70338c97d8)
  Executable unittests src/bin/nsproxy.rs (target/debug/deps/nsproxy-7498efc801f1336f)
  Executable unittests src/bin/tcproxy.rs (target/debug/deps/tcproxy-8bb0a5ffc17989d2)

        ";
        let paths = extract_executable_paths(stdout);
        dbg!(paths);
    }

    #[test]
    fn test_extract_test_names() {
        let output = "\
util::get_all_child_pids: test
util::t_pidfd: test
util::test_flatpakperm: test
util::test_substitute_argv: test
watcher::test_parse_flatpak_info: test

5 tests, 0 benchmarks
        ";

        dbg!(extract_test_names(output));
    }

    #[tokio::test]
    async fn test_run_test() {
        let binary = "./target/debug/deps/netns_proxy-0b269e570007cd4d";
        let test_name = "util::get_all_child_pids";

        assert!(run_test(binary, test_name).await.is_ok());
    }
}
