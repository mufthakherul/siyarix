use pyo3::prelude::*;
use pyo3::types::PyDict;
use roxmltree::Document;
use serde_json::Value;

fn severity_for_port(port: u16) -> &'static str {
    match port {
        23 | 445 | 3389 | 5900 | 6379 | 9200 | 27017 => "high",
        21 | 25 | 110 | 111 | 135 | 139 | 143 | 161 | 389 | 2049 | 3306 | 5432 => "medium",
        22 | 53 => "low",
        _ => "info",
    }
}

#[pyfunction]
fn parse_nmap_xml(py: Python<'_>, xml_output: &str) -> PyResult<Vec<Py<PyDict>>> {
    let doc = Document::parse(xml_output)
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(format!("invalid nmap xml: {err}")))?;

    let mut findings: Vec<Py<PyDict>> = Vec::new();
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let target = host
            .descendants()
            .find(|n| n.has_tag_name("address"))
            .and_then(|n| n.attribute("addr"))
            .unwrap_or("unknown");

        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            let state_open = port
                .children()
                .find(|n| n.has_tag_name("state"))
                .and_then(|n| n.attribute("state"))
                .map(|s| s == "open")
                .unwrap_or(false);
            if !state_open {
                continue;
            }
            let port_id = port
                .attribute("portid")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(0);
            let protocol = port.attribute("protocol").unwrap_or("tcp");
            let service = port
                .children()
                .find(|n| n.has_tag_name("service"))
                .and_then(|n| n.attribute("name"))
                .unwrap_or("unknown");

            let finding = PyDict::new(py);
            finding.set_item("title", format!("Open port {port_id}/{protocol} ({service})"))?;
            finding.set_item("severity", severity_for_port(port_id))?;
            finding.set_item(
                "description",
                format!("Port {port_id}/{protocol} is open — service: {service}"),
            )?;
            finding.set_item("evidence", format!("{target}:{port_id}/{protocol}"))?;
            finding.set_item("tool", "nmap")?;
            finding.set_item("target", target)?;
            findings.push(finding.into());
        }
    }
    Ok(findings)
}

#[pyfunction]
fn parse_nuclei_json(py: Python<'_>, json_output: &str) -> PyResult<Vec<Py<PyDict>>> {
    let data: Vec<Value> = serde_json::from_str(json_output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid nuclei json: {e}")))?;

    let mut findings: Vec<Py<PyDict>> = Vec::new();
    for item in data {
        let finding = PyDict::new(py);
        let template = item.get("template").and_then(|v| v.as_str()).unwrap_or("unknown");
        let severity = item.get("info").and_then(|i| i.get("severity")).and_then(|v| v.as_str()).unwrap_or("medium");
        let name = item.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("Unknown finding");
        let target = item.get("host").and_then(|v| v.as_str()).unwrap_or("");

        finding.set_item("title", name)?;
        finding.set_item("severity", severity)?;
        finding.set_item("description", format!("Nuclei finding: {name}"))?;
        finding.set_item("evidence", template)?;
        finding.set_item("tool", "nuclei")?;
        finding.set_item("target", target)?;
        findings.push(finding.into());
    }
    Ok(findings)
}

#[pyfunction]
fn parse_nikto_txt(py: Python<'_>, txt_output: &str) -> PyResult<Vec<Py<PyDict>>> {
    let mut findings: Vec<Py<PyDict>> = Vec::new();
    for line in txt_output.lines() {
        if line.contains("+ ") && (line.contains("OPTIONS") || line.contains("security") || line.contains("vulnerable")) {
            let finding = PyDict::new(py);
            finding.set_item("title", "Nikto finding detected")?;
            finding.set_item("severity", "medium")?;
            finding.set_item("description", line.to_string())?;
            finding.set_item("evidence", line.to_string())?;
            finding.set_item("tool", "nikto")?;
            findings.push(finding.into());
        }
    }
    Ok(findings)
}

#[pyfunction]
fn parse_gobuster_txt(py: Python<'_>, txt_output: &str) -> PyResult<Vec<Py<PyDict>>> {
    let mut findings: Vec<Py<PyDict>> = Vec::new();
    for line in txt_output.lines() {
        if line.starts_with("/") && !line.contains("Progress:") {
            let finding = PyDict::new(py);
            finding.set_item("title", format!("Directory found: {line}"))?;
            finding.set_item("severity", "info")?;
            finding.set_item("description", format!("Directory enumeration: {line}"))?;
            finding.set_item("evidence", line.to_string())?;
            finding.set_item("tool", "gobuster")?;
            findings.push(finding.into());
        }
    }
    Ok(findings)
}

#[pymodule]
fn nexsec_rust_parsers(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(parse_nmap_xml, module)?)?;
    module.add_function(wrap_pyfunction!(parse_nuclei_json, module)?)?;
    module.add_function(wrap_pyfunction!(parse_nikto_txt, module)?)?;
    module.add_function(wrap_pyfunction!(parse_gobuster_txt, module)?)?;
    Ok(())
}
