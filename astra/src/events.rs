use near_sdk::serde::Serialize;
use serde_json::json;

use common::{EventPayload, NearEvent};

fn emit_event<T: Serialize>(event: EventPayload<T>) {
    NearEvent {
        standard: "astra++",
        version: "1.0.0",
        event,
    }
    .emit();
}

pub(crate) fn emit_veto(prop_id: u64) {
    emit_event(EventPayload {
        event: "veto",
        data: json!({ "prop_id": prop_id }),
    });
}

pub(crate) fn emit_dissolve() {
    emit_event(EventPayload {
        event: "dissolve",
        data: "dao is dissolved",
    })
}

#[cfg(test)]
mod unit_tests {
    use near_sdk::{test_utils};

    use super::*;

    #[test]
    fn log_hooks() {
        let expected1 = r#"EVENT_JSON:{"standard":"astra++","version":"1.0.0","event":"veto","data":{"prop_id":21}}"#;
        let expected2 = r#"EVENT_JSON:{"standard":"astra++","version":"1.0.0","event":"dissolve","data":"dao is dissolved"}"#;
        emit_veto(21);
        assert_eq!(vec![expected1], test_utils::get_logs());
        emit_dissolve();
        assert_eq!(vec![expected1, expected2], test_utils::get_logs());
    }
}
