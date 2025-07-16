//! MPC Fixture
//!
//! Create an isolated MPC network for testing without hitting a real network.

pub mod builder;
pub mod fixture_interface;
pub mod fixture_tasks;
pub mod input;
pub mod mock_governance;

pub use builder::MpcFixtureBuilder;
pub use fixture_interface::{MpcFixture, MpcFixtureNode};
