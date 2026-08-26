#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus<'a> {
    Running,
    Succeeded,
    Failed { error_code: &'a str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationStatusDocument<'a> {
    pub operation_id: &'a str,
    pub target_probe_version: &'a str,
    pub status: OperationStatus<'a>,
    pub repair_eligibility: Option<RepairEligibilityDocument<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairEligibilityDocument<'a> {
    pub canonical_evidence: &'a str,
    pub signature: &'a str,
}

impl OperationStatusDocument<'_> {
    #[must_use]
    pub fn encode(self) -> String {
        let status = match self.status {
            OperationStatus::Running => "running",
            OperationStatus::Succeeded => "succeeded",
            OperationStatus::Failed { .. } => "failed",
        };
        let mut contents = format!(
            "operation_id = {:?}\ntarget_probe_version = {:?}\nstatus = {:?}\n",
            self.operation_id, self.target_probe_version, status,
        );
        if let OperationStatus::Failed { error_code } = self.status {
            contents.push_str(&format!("error_code = {error_code:?}\nmessage = \"\"\n"));
        }
        if let Some(eligibility) = self.repair_eligibility {
            contents.push_str(&format!(
                "repair_eligibility_evidence = {:?}\nrepair_eligibility_signature = {:?}\n",
                eligibility.canonical_evidence, eligibility.signature,
            ));
        }
        contents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_single_probe_operation_status_format() {
        assert_eq!(
            OperationStatusDocument {
                operation_id: "42",
                target_probe_version: "1.2.3",
                status: OperationStatus::Failed {
                    error_code: "lifecycle.repair_unresolved",
                },
                repair_eligibility: None,
            }
            .encode(),
            "operation_id = \"42\"\ntarget_probe_version = \"1.2.3\"\nstatus = \"failed\"\nerror_code = \"lifecycle.repair_unresolved\"\nmessage = \"\"\n"
        );
    }
}
