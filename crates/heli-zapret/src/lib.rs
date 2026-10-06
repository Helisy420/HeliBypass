//! DPI-bypass orchestration around zapret's `winws.exe` (Windows).
//!
//! `winws.exe` + WinDivert is the packet engine; it is kept as-is (it is a mature C codebase
//! working at the kernel-driver boundary, and rewriting it would add risk, not speed). This
//! crate replaces everything *around* it that the upstream project does with batch files and
//! PowerShell: strategy selection, game filter, list management, the Windows service,
//! diagnostics and strategy testing.

pub mod builder;
pub mod bundle;
pub mod diagnostics;
pub mod engine;
pub mod lists;
pub mod probe;
pub mod proc;
pub mod scm;
pub mod service;
pub mod strategy;
pub mod tester;
pub mod userlists;
