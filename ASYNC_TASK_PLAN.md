# Plan for Converting SignatureTask to Async

## Current Architecture
- SignatureTask is a struct with synchronous methods
- Methods are called from handle_posit_message and handle_task_result
- Task state is queried and mutated directly

## Target Architecture
- SignatureTask becomes an async function/task
- Task runs independently, receives messages via channel
- Spawned into JoinMap keyed by SignId
- Returns Result<(), SignError>

## Implementation Steps
1. Create async task function signature
2. Add message channel for receiving posit messages
3. Convert posit handling into async loop
4. Integrate generation spawning
5. Replace all task.insert() with tasks.spawn()
6. Replace all task.get_mut() with channel sends
7. Handle task completion via join_next()

## Key Changes
- task_channels: HashMap<SignId, mpsc::Sender<TaskMessage>>
- Spawn: tasks.spawn(sign_id, run_signature_task(...))
- Message: task_channels.get(&sign_id).unwrap().send(msg).await
- Completion: join_next() removes from both maps
