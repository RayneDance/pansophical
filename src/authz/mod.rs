//! Authorization engine: key resolution, rule evaluation,
//! intersection computation, and explain mode.

pub mod intersection;
pub mod glob;

#[cfg(test)]
mod tests;
