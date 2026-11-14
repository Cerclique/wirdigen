//! Where each input is read from and where its Dissector goes (spec §9.2, §9.3).
//!
//! Every check here runs before any input is read, so a usage error leaves nothing done.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// The `Source` name of standard input.
const STDIN_NAME: &str = "<stdin>";

/// One input argument: a path, or `-` for standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Input {
    Stdin,
    File(PathBuf),
}

impl Input {
    /// The `Source` name: the path as typed, or `<stdin>`.
    pub(crate) fn name(&self) -> Cow<'_, str> {
        match self {
            Input::Stdin => Cow::Borrowed(STDIN_NAME),
            Input::File(path) => path.to_string_lossy(),
        }
    }
}

/// Where one Dissector is written: a file, or `-` for standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Output {
    Stdout,
    File(PathBuf),
}

impl Output {
    pub(crate) fn from_arg(arg: PathBuf) -> Self {
        if is_dash(&arg) { Output::Stdout } else { Output::File(arg) }
    }

    /// How a message names this output after a verb: `to standard output`, or the path in
    /// backticks.
    pub(crate) fn target(&self) -> String {
        match self {
            Output::Stdout => "to standard output".to_owned(),
            Output::File(path) => format!("`{}`", path.display()),
        }
    }
}

/// How `generate` places its outputs, from `-o` and `--out-dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Next to each input; standard input goes to standard output.
    NextToInput,
    /// `-o <file|->`, for exactly one input.
    Single(Output),
    /// `--out-dir <dir>`; standard input still goes to standard output.
    Dir(PathBuf),
}

impl Placement {
    /// The placement for `-o` and `--out-dir`, which clap keeps from being given together.
    pub(crate) fn from_args(output: Option<PathBuf>, out_dir: Option<PathBuf>) -> Self {
        match (output, out_dir) {
            (Some(output), _) => Placement::Single(Output::from_arg(output)),
            (None, Some(dir)) => Placement::Dir(dir),
            (None, None) => Placement::NextToInput,
        }
    }
}

/// A mistake in how `generate` or `validate` was called, found before any input is read. Each one
/// exits with clap's usage error, code 2.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UsageError {
    #[error("`-` (standard input) can be given at most once")]
    StdinTwice,
    #[error("`-o` requires exactly one input, but {count} were given")]
    OutputNeedsOneInput { count: usize },
    #[error("the Dissector of `{input}` would overwrite the input `{overwritten}`")]
    OverwritesInput { input: String, overwritten: String },
    #[error("`{first}` and `{second}` would both be written to `{}`", .output.display())]
    SameOutput { first: String, second: String, output: PathBuf },
    #[error("`--check` compares files, so it cannot be used with `-o -`")]
    CheckWithDashOutput,
    #[error("`--check` compares files, but the Dissector of `{input}` goes to standard output; give `-o <FILE>`")]
    CheckToStdout { input: String },
    #[error("`--message-format json` writes to standard output, so it cannot be used with `-o -`")]
    JsonWithDashOutput,
    #[error(
        "`--message-format json` writes to standard output, but so does the Dissector of `{input}`; give `-o <FILE>`"
    )]
    JsonAndDissectorToStdout { input: String },
}

/// Turns input arguments into inputs, rejecting `-` given more than once.
pub(crate) fn inputs(args: Vec<PathBuf>) -> Result<Vec<Input>, UsageError> {
    let inputs: Vec<Input> =
        args.into_iter().map(|arg| if is_dash(&arg) { Input::Stdin } else { Input::File(arg) }).collect();
    if inputs.iter().filter(|input| **input == Input::Stdin).count() > 1 {
        return Err(UsageError::StdinTwice);
    }
    Ok(inputs)
}

/// The output of each input, in order, rejecting `-o` with other than one input, two inputs
/// written to one file, and an output that is an input. Paths are compared after joining them
/// to `cwd` and folding `.` and `..`, without touching the file system.
pub(crate) fn outputs(inputs: &[Input], placement: &Placement, cwd: &Path) -> Result<Vec<Output>, UsageError> {
    if matches!(placement, Placement::Single(_)) && inputs.len() != 1 {
        return Err(UsageError::OutputNeedsOneInput { count: inputs.len() });
    }
    let outputs: Vec<Output> = inputs.iter().map(|input| output_of(input, placement)).collect();

    let input_paths: HashMap<PathBuf, &Input> = inputs
        .iter()
        .filter_map(|input| match input {
            Input::File(path) => Some((normalize(cwd, path), input)),
            Input::Stdin => None,
        })
        .collect();
    let mut written: HashMap<PathBuf, &Input> = HashMap::new();
    for (input, output) in inputs.iter().zip(&outputs) {
        let Output::File(path) = output else { continue };
        let key = normalize(cwd, path);
        if let Some(overwritten) = input_paths.get(&key) {
            return Err(UsageError::OverwritesInput {
                input: input.name().into_owned(),
                overwritten: overwritten.name().into_owned(),
            });
        }
        if let Some(first) = written.insert(key, input) {
            return Err(UsageError::SameOutput {
                first: first.name().into_owned(),
                second: input.name().into_owned(),
                output: path.clone(),
            });
        }
    }
    Ok(outputs)
}

/// The file of each output under `generate --check`, which compares files, rejecting any Dissector
/// bound for standard output.
pub(crate) fn output_files(
    inputs: &[Input],
    placement: &Placement,
    outputs: Vec<Output>,
) -> Result<Vec<PathBuf>, UsageError> {
    inputs
        .iter()
        .zip(outputs)
        .map(|(input, output)| match output {
            Output::File(path) => Ok(path),
            Output::Stdout if matches!(placement, Placement::Single(_)) => Err(UsageError::CheckWithDashOutput),
            Output::Stdout => Err(UsageError::CheckToStdout { input: input.name().into_owned() }),
        })
        .collect()
}

/// Rejects any Dissector bound for standard output, which `--message-format json` writes its
/// records to.
pub(crate) fn reject_stdout_under_json(
    inputs: &[Input],
    placement: &Placement,
    outputs: &[Output],
) -> Result<(), UsageError> {
    let Some((input, _)) = inputs.iter().zip(outputs).find(|(_, output)| **output == Output::Stdout) else {
        return Ok(());
    };
    Err(if matches!(placement, Placement::Single(_)) {
        UsageError::JsonWithDashOutput
    } else {
        UsageError::JsonAndDissectorToStdout { input: input.name().into_owned() }
    })
}

/// Whether an argument is `-`, standing for standard input or output.
fn is_dash(arg: &Path) -> bool {
    arg.as_os_str() == "-"
}

fn output_of(input: &Input, placement: &Placement) -> Output {
    match (input, placement) {
        (_, Placement::Single(output)) => output.clone(),
        (Input::Stdin, _) => Output::Stdout,
        (Input::File(path), Placement::NextToInput) => Output::File(next_to(path)),
        (Input::File(path), Placement::Dir(dir)) => {
            let file_name = path.file_name().map_or(path.as_path(), Path::new);
            Output::File(dir.join(next_to(file_name)))
        }
    }
}

/// The Dissector path next to `input`: `foo.wirdigen.yaml` gives `foo.lua`, any other name has
/// its last extension replaced.
fn next_to(input: &Path) -> PathBuf {
    match input.file_name().and_then(|name| name.to_str()).and_then(|name| name.strip_suffix(".wirdigen.yaml")) {
        Some(stem) => input.with_file_name(format!("{stem}.lua")),
        None => input.with_extension("lua"),
    }
}

/// `path` joined to `cwd`, with `.` dropped and `..` taking off the previous normal component.
///
/// A `..` with no normal component before it is kept on a relative path, so `../x` never equals
/// `x` when `cwd` is empty, and dropped after a root or prefix, since `/..` is `/`.
fn normalize(cwd: &Path, path: &Path) -> PathBuf {
    let mut normal: Vec<Component<'_>> = Vec::new();
    let joined = cwd.join(path);
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normal.last() {
                Some(Component::Normal(_)) => {
                    normal.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                None | Some(Component::ParentDir | Component::CurDir) => normal.push(component),
            },
            other => normal.push(other),
        }
    }
    normal.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> Vec<Input> {
        names.iter().map(|name| Input::File(PathBuf::from(name))).collect()
    }

    #[test]
    fn stdin_given_twice_is_a_usage_error() {
        let args = vec![PathBuf::from("-"), PathBuf::from("a.yaml"), PathBuf::from("-")];
        assert!(matches!(inputs(args), Err(UsageError::StdinTwice)));
    }

    #[test]
    fn single_output_needs_exactly_one_input() {
        let placement = Placement::Single(Output::File(PathBuf::from("out.lua")));
        let result = outputs(&files(&["a.yaml", "b.yaml"]), &placement, Path::new("/work"));
        assert!(matches!(result, Err(UsageError::OutputNeedsOneInput { count: 2 })));
    }

    #[test]
    fn output_overwriting_an_input_is_a_usage_error() {
        let placement = Placement::Single(Output::File(PathBuf::from("./a.yaml")));
        let result = outputs(&files(&["a.yaml"]), &placement, Path::new("/work"));
        let Err(UsageError::OverwritesInput { input, overwritten }) = result else { panic!("{result:?}") };
        assert_eq!((input.as_str(), overwritten.as_str()), ("a.yaml", "a.yaml"));
    }

    #[test]
    fn two_inputs_to_one_output_is_a_usage_error() {
        let placement = Placement::Dir(PathBuf::from("out"));
        let result = outputs(&files(&["x/p.yaml", "y/p.yaml"]), &placement, Path::new("/work"));
        let Err(UsageError::SameOutput { first, second, output }) = result else { panic!("{result:?}") };
        assert_eq!((first.as_str(), second.as_str()), ("x/p.yaml", "y/p.yaml"));
        assert_eq!(output, PathBuf::from("out/p.lua"));
    }

    #[test]
    fn check_rejects_dash_output() {
        let inputs = files(&["a.yaml"]);
        let placement = Placement::Single(Output::Stdout);
        let result = output_files(&inputs, &placement, vec![Output::Stdout]);
        assert!(matches!(result, Err(UsageError::CheckWithDashOutput)));
    }

    #[test]
    fn check_rejects_stdin_going_to_standard_output() {
        let inputs = vec![Input::Stdin];
        let result = output_files(&inputs, &Placement::NextToInput, vec![Output::Stdout]);
        let Err(UsageError::CheckToStdout { input }) = result else { panic!("{result:?}") };
        assert_eq!(input, "<stdin>");
    }

    #[test]
    fn json_rejects_dash_output() {
        let inputs = files(&["a.yaml"]);
        let placement = Placement::Single(Output::Stdout);
        let result = reject_stdout_under_json(&inputs, &placement, &[Output::Stdout]);
        assert!(matches!(result, Err(UsageError::JsonWithDashOutput)));
    }

    #[test]
    fn json_rejects_stdin_going_to_standard_output() {
        let inputs = vec![Input::File(PathBuf::from("a.yaml")), Input::Stdin];
        let outputs = [Output::File(PathBuf::from("a.lua")), Output::Stdout];
        let result = reject_stdout_under_json(&inputs, &Placement::NextToInput, &outputs);
        let Err(UsageError::JsonAndDissectorToStdout { input }) = result else { panic!("{result:?}") };
        assert_eq!(input, "<stdin>");
    }

    #[test]
    fn json_accepts_file_outputs() {
        let inputs = files(&["a.yaml"]);
        let result = reject_stdout_under_json(&inputs, &Placement::NextToInput, &[Output::File("a.lua".into())]);
        assert!(result.is_ok());
    }

    #[test]
    fn a_leading_parent_of_a_relative_path_is_kept() {
        assert_eq!(normalize(Path::new(""), Path::new("../x")), PathBuf::from("../x"));
        assert_eq!(normalize(Path::new(""), Path::new("a/../../x")), PathBuf::from("../x"));
    }

    #[test]
    fn a_parent_after_the_root_is_dropped() {
        assert_eq!(normalize(Path::new(""), Path::new("/..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new(""), Path::new("/a/../..")), PathBuf::from("/"));
    }

    #[test]
    fn without_a_working_directory_a_parent_input_is_not_the_output() {
        let placement = Placement::Single(Output::File(PathBuf::from("x.wirdigen.yaml")));
        let result = outputs(&files(&["../x.wirdigen.yaml"]), &placement, Path::new(""));
        assert_eq!(result.unwrap(), vec![Output::File(PathBuf::from("x.wirdigen.yaml"))]);
    }

    #[test]
    fn without_a_working_directory_two_inputs_to_one_output_is_a_usage_error() {
        let placement = Placement::Dir(PathBuf::from("out"));
        let result = outputs(&files(&["x/p.yaml", "y/p.yaml"]), &placement, Path::new(""));
        let Err(UsageError::SameOutput { first, second, output }) = result else { panic!("{result:?}") };
        assert_eq!((first.as_str(), second.as_str()), ("x/p.yaml", "y/p.yaml"));
        assert_eq!(output, PathBuf::from("out/p.lua"));
    }

    #[test]
    fn an_output_names_itself_as_a_target() {
        assert_eq!(Output::Stdout.target(), "to standard output");
        assert_eq!(Output::File(PathBuf::from("out/a.lua")).target(), "`out/a.lua`");
    }
}
