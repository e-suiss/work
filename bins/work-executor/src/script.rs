//! The step script the executor runs for every commitment it is given (T-105 item 1): the only external action it takes is its own configurable sequence of steps, so that every branch of the coordination contract runs over the real network with the real Access: `wait <ms>`, `write <summary>` (an action report bound to the delivery's authority context and idempotency key, SEC-15), `fail <reason>` and `silent` (no heartbeat and no answer from then on). A step may carry a name, `name: step`, which the capability's `non_cancellable` list names (RC-39); an unnamed step is `step-<n>`, counted from 1.

use work_kernel::control::body::{MAX_NAME, MAX_REASON, MAX_TEXT};

/// One step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Wait this many milliseconds.
    Wait(u64),
    /// Report an external action with this summary (SEC-15).
    Write(String),
    /// End the attempt as failed with this reason.
    Fail(String),
    /// Stop heartbeats and answer nothing from now on.
    Silent,
}

/// A step and its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Named {
    /// The name the capability's `non_cancellable` list may name (RC-39).
    pub(crate) name: String,
    /// The step.
    pub(crate) step: Step,
}

/// The script.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Script {
    /// The steps, in order.
    pub(crate) steps: Vec<Named>,
}

/// Why a step does not parse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("script step {index}: {why}")]
pub(crate) struct ScriptError {
    /// The step, from 1.
    pub(crate) index: usize,
    /// Why.
    pub(crate) why: &'static str,
}

fn step(text: &str) -> Result<Step, &'static str> {
    let text = text.trim();
    let (verb, rest) = text.split_once(' ').unwrap_or((text, ""));
    let rest = rest.trim();
    match verb {
        "wait" => rest
            .parse::<u64>()
            .map(Step::Wait)
            .map_err(|_| "wait takes milliseconds"),
        "write" if !rest.is_empty() && rest.len() <= MAX_TEXT => Ok(Step::Write(rest.to_owned())),
        "write" => Err("write takes a summary of 1 to 4096 bytes"),
        "fail" if !rest.is_empty() && rest.len() <= MAX_REASON => Ok(Step::Fail(rest.to_owned())),
        "fail" => Err("fail takes a reason of 1 to 1024 bytes"),
        "silent" if rest.is_empty() => Ok(Step::Silent),
        "silent" => Err("silent takes nothing"),
        _ => Err("a step is wait, write, fail or silent"),
    }
}

fn named(index: usize, text: &str) -> Result<Named, &'static str> {
    let verbs = ["wait", "write", "fail", "silent"];
    let (name, rest) = match text.split_once(':') {
        Some((name, rest))
            if !name.trim().is_empty()
                && !name.contains(' ')
                && !verbs.iter().any(|v| text.trim_start().starts_with(v)) =>
        {
            (name.trim().to_owned(), rest)
        }
        _ => (format!("step-{index}"), text),
    };
    if name.len() > MAX_NAME {
        return Err("a step name is 1 to 256 bytes");
    }
    Ok(Named {
        name,
        step: step(rest)?,
    })
}

impl Script {
    /// Parses one step per line of `lines`.
    pub(crate) fn parse(lines: &[String]) -> Result<Self, ScriptError> {
        let steps = lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let index = i.saturating_add(1);
                named(index, line).map_err(|why| ScriptError { index, why })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { steps })
    }
}

/// Where one run of the script stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    next: usize,
    done: Vec<String>,
}

/// What the run does next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Next<'s> {
    /// Run this step.
    Step(&'s Named),
    /// Every step ran: the attempt succeeded.
    Completed,
}

impl Run {
    /// A run from the first step.
    pub(crate) const fn new() -> Self {
        Self {
            next: 0,
            done: Vec::new(),
        }
    }

    /// The step to run now.
    pub(crate) fn next<'s>(&self, script: &'s Script) -> Next<'s> {
        script
            .steps
            .get(self.next)
            .map_or(Next::Completed, Next::Step)
    }

    /// Marks the step under way as done.
    pub(crate) fn advance(&mut self, script: &Script) {
        if let Some(s) = script.steps.get(self.next) {
            self.done.push(s.name.clone());
        }
        self.next = self.next.saturating_add(1);
    }

    /// The name of the step under way, if any.
    pub(crate) fn current<'s>(&self, script: &'s Script) -> Option<&'s str> {
        script.steps.get(self.next).map(|s| s.name.as_str())
    }

    /// What was done, for a status report.
    pub(crate) fn done(&self) -> String {
        let text = self.done.join(", ");
        if text.len() > MAX_TEXT {
            let mut cut = MAX_TEXT;
            while !text.is_char_boundary(cut) {
                cut = cut.saturating_sub(1);
            }
            text.get(..cut).unwrap_or_default().to_owned()
        } else {
            text
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(all: &[&str]) -> Vec<String> {
        all.iter().map(|s| (*s).to_owned()).collect()
    }

    // T-105
    #[test]
    fn t_105_a_script_is_wait_write_fail_and_silent_steps_with_optional_names() {
        let script = Script::parse(&lines(&[
            "wait 250",
            "deploy: write deployed version 3",
            "fail the target refused",
            "silent",
        ]))
        .unwrap();
        assert_eq!(
            script.steps,
            vec![
                Named {
                    name: "step-1".to_owned(),
                    step: Step::Wait(250)
                },
                Named {
                    name: "deploy".to_owned(),
                    step: Step::Write("deployed version 3".to_owned())
                },
                Named {
                    name: "step-3".to_owned(),
                    step: Step::Fail("the target refused".to_owned())
                },
                Named {
                    name: "step-4".to_owned(),
                    step: Step::Silent
                },
            ]
        );
        let colon = Script::parse(&lines(&["write status: green"])).unwrap();
        assert_eq!(colon.steps[0].name, "step-1");
        assert_eq!(colon.steps[0].step, Step::Write("status: green".to_owned()));
        for bad in [
            "wait",
            "wait later",
            "write",
            "fail",
            "silent now",
            "jump 3",
            "",
        ] {
            let refused = Script::parse(&lines(&["wait 1", bad])).unwrap_err();
            assert_eq!(refused.index, 2, "{bad}");
        }
    }

    // T-105 RC-39 RC-42
    #[test]
    fn t_105_a_run_steps_through_the_script_and_names_the_step_under_way() {
        let script = Script::parse(&lines(&["wait 1", "deploy: write done"])).unwrap();
        let mut run = Run::new();
        assert_eq!(run.current(&script), Some("step-1"));
        assert!(matches!(run.next(&script), Next::Step(s) if s.step == Step::Wait(1)));
        run.advance(&script);
        assert_eq!(run.current(&script), Some("deploy"));
        run.advance(&script);
        assert_eq!(run.current(&script), None);
        assert_eq!(run.next(&script), Next::Completed);
        assert_eq!(run.done(), "step-1, deploy");
    }
}
