#![feature(lazy_cell)]
#![feature(lazy_cell_consume)]
mod chacha;
mod dh;
mod poly1305;
mod util;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::wrap_pymodule;

#[pymodule]
fn encryption(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(chacha::chacha))?;
    m.add_wrapped(wrap_pymodule!(dh::dh))?;

    // inject into sys.modules
    let sys = PyModule::import(py, "sys")?;
    let sys_modules: &PyDict = sys.getattr("modules")?.downcast()?;
    sys_modules.set_item("encryption.chacha", m.getattr("chacha")?)?;
    sys_modules.set_item("encryption.dh", m.getattr("dh")?)?;
    Ok(())
}
