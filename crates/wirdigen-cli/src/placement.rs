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
pub enum Input {
    Stdin,
    File(PathBuf),
}

impl Input {
    /// The `Source` name: the path as typed, or `<stdin>`.
    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Input::Stdin => Cow::Borrowed(STDIN_NAME),
            Input::File(path) => path.to_string_lossy(),
        }
    }
}

/// Where one Dissector is written: a file, or `-` for standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Stdout,
    File(PathBuf),
}

impl Output {
    pub fn from_arg(arg: PathBuf) -> Self {
        if is_dash(&arg) { Output::Stdout } else { Output::File(arg) }
    }
}

/// How `generate` places its outputs, from `-o` and `--out-dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Next to each input; standard input goes to standard output.
    NextToInput,
    /// `-o <file|->`, for exactly one input.
    Single(Output),
    /// `--out-dir <dir>`; standard input still goes to standard output.
    Dir(PathBuf),
}

impl Placement {
    /// The placement for `-o` and `--out-dir`, which clap keeps from being given together.
    pub fn from_args(output: Option<PathBuf>, out_dir: Option<PathBuf>) -> Self {
        match (output, out_dir) {
            (Some(output), _) => Placement::Single(Output::from_arg(output)),
            (None, Some(dir)) => Placement::Dir(dir),
            (None, None) => Placement::NextToInput,
        }
    }
}

/// Turns input arguments into inputs, rejecting `-` given more than once.
pub fn inputs(args: Vec<PathBuf>) -> Result<Vec<Input>, String> {
    let inputs: Vec<Input> =
        args.into_iter().map(|arg| if is_dash(&arg) { Input::Stdin } else { Input::File(arg) }).collect();
    if inputs.iter().filter(|input| **input == Input::Stdin).count() > 1 {
        return Err("`-` (standard input) can be given at most once".to_owned());
    }
    Ok(inputs)
}

/// The output of each input, in order, rejecting `-o` with other than one input, two inputs
/// written to one file, and an output that is an input. Paths are compared after joining them
/// to `cwd` and folding `.` and `..`, without touching the file system.
pub fn outputs(inputs: &[Input], placement: &Placement, cwd: &Path) -> Result<Vec<Output>, String> {
    if matches!(placement, Placement::Single(_)) && inputs.len() != 1 {
        return Err(format!("`-o` requires exactly one input, but {} were given", inputs.len()));
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
            return Err(format!(
                "the Dissector of `{}` would overwrite the input `{}`",
                input.name(),
                overwritten.name()
            ));
        }
        if let Some(first) = written.insert(key, input) {
            return Err(format!(
                "`{}` and `{}` would both be written to `{}`",
                first.name(),
                input.name(),
                path.display()
            ));
        }
    }
    Ok(outputs)
}

/// The file of each output under `generate --check`, which compares files, rejecting any Dissector
/// bound for standard output.
pub fn output_files(inputs: &[Input], placement: &Placement, outputs: Vec<Output>) -> Result<Vec<PathBuf>, String> {
    inputs
        .iter()
        .zip(outputs)
        .map(|(input, output)| match output {
            Output::File(path) => Ok(path),
            Output::Stdout if matches!(placement, Placement::Single(_)) => {
                Err("`--check` compares files, so it cannot be used with `-o -`".to_owned())
            }
            Output::Stdout => Err(format!(
                "`--check` compares files, but the Dissector of `{}` goes to standard output; give `-o <FILE>`",
                input.name()
            )),
        })
        .collect()
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

/// `path` joined to `cwd`, with `.` dropped and `..` taking off the previous component.
fn normalize(cwd: &Path, path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in cwd.join(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal
}
