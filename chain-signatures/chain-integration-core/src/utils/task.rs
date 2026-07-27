/// Aborts the wrapped task on drop, preventing a leaked background task when
/// the owner (e.g. an indexer `run()` loop) is dropped or cancelled.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
