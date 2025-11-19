//! A debug page showing a live view of what the node it currently doing.

use alloy_primitives::map::HashMap;
use axum::response::Html;
use axum::Extension;
use maud::{html, Markup, Render};
use std::sync::Arc;
use std::{sync::LazyLock, time::Instant};
use tokio::sync::{watch, Mutex, RwLock};

use crate::web::AxumState;

/// Global state used for easy access.
///
/// Using global state is a bit of a code-smell but it really helps to make it
/// accessible from everywhere. Passing in a debug data to all tokio tasks that
/// that need monitoring is going to be far worse for code maintainability.
///
/// One non-trivial problem with global state is testability. Running multiple
/// nodes in the same process is normal for testing. These end up sharing the
/// same global state. To give each node a "private" share of the state, the
/// state is separate for each node.
///
/// Unfortunately, this means each code place accessing global state must have a
/// way to identify the node. Currently, account_id serialized to a String is
/// used to identify the node. (Still looking for a better solution...)
///
/// The outer RwLock should only be used in write mode once per node to
/// initialize. All future calls are read-only and therefore will not create
/// cross-node lock contention.
static TASK_REGISTRY: LazyLock<RwLock<HashMap<String, LocalTaskRegistry>>> =
    LazyLock::new(Default::default);
type LocalTaskRegistry = Arc<Mutex<Vec<DebugPageTask>>>;

async fn read_registry(account_id: &str) -> LocalTaskRegistry {
    // first try a read lock - this should be the common case
    {
        let map = TASK_REGISTRY.read().await;
        if let Some(tasks) = map.get(account_id) {
            return Arc::clone(tasks);
        }
    }
    // once per node: take a write lock and initialize
    let mut map = TASK_REGISTRY.write().await;
    Arc::clone(
        map.entry(account_id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new()))),
    )
}

/// Register a task to be displayed on the debug page.
///
/// Returns a [`DebugPageTaskHandle`] that can be used to update the displayed
/// content. Note that the debug page will display outdated information if the
/// content is not updated frequently.
///
/// When the returned [`DebugPageTaskHandle`] is dropped, it's information is
/// also removed from the debug page.
pub fn register_task(node_account_id: String, name: String) -> DebugPageTaskHandle {
    let (sender, receiver) = watch::channel(html! {p{"uninitialized task state"}});
    let task = DebugPageTask {
        name,
        registered: Instant::now(),
        state: receiver,
    };
    let node_id = node_account_id.to_string();
    // spawn it here to avoid `async` on the interface
    tokio::spawn(async move {
        read_registry(&node_id).await.lock().await.push(task);
    });
    DebugPageTaskHandle {
        sender,
        node_account_id,
    }
}

/// Unregister task by it's channel, since the name may not be unique.
async fn unregister_task(account_id: &str, rx: &watch::Receiver<Markup>) {
    let registry = read_registry(account_id).await;
    let mut tasks = registry.lock().await;
    tasks.retain(|task| !task.state.same_channel(rx));
}

pub(super) async fn page(Extension(web): Extension<Arc<AxumState>>) -> Html<String> {
    let registry = read_registry(web.my_account_id.as_str()).await;
    let tasks = registry.lock().await;

    let markup = html! {
        h1 { "Registered Tasks (" (tasks.len())  ")"}
        style {
            ".tasks { display: flex; flex-wrap: wrap; }"
            ".task { margin: 1rem; padding: 1rem; border: solid 1px; }"
            ".task-title { font-weight: bold; }"
        }

        .tasks {
            @for task in tasks.iter() {
                @let age = format!("{:#.2?}", task.registered.elapsed());
                .task {
                    .task-title {
                        (task.name)
                    }
                    .task-state {
                        "age: " (age)
                        (task.state.borrow().render())
                    }
                }
            }
        }
    };
    Html(markup.into_string())
}

pub struct DebugPageTask {
    name: String,
    registered: Instant,
    state: watch::Receiver<Markup>,
}

pub struct DebugPageTaskHandle {
    sender: watch::Sender<Markup>,
    node_account_id: String,
}

impl DebugPageTaskHandle {
    pub fn send(&self, markup: Markup) {
        self.sender
            .send(markup)
            .expect("sender should live longer than handles")
    }
}
impl Drop for DebugPageTaskHandle {
    fn drop(&mut self) {
        // memory swap trick to avoid cloning the id right before it gets dropped anyway
        let mut take_account_id = String::new();
        std::mem::swap(&mut self.node_account_id, &mut take_account_id);
        let rx = self.sender.subscribe();
        tokio::spawn(async move {
            unregister_task(&take_account_id, &rx).await;
        });
    }
}
