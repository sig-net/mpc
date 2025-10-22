Posits no longer make sense in the context of these tasks now, since each `TripleTask`/`PresignatureTask`/`SignatureTask` only needs one singular posit, meanwhile `Posits` holds many at the same time. Refactor `Posits` into just `Posit` so that we just have a singular posit that needs to be acted upon.


## Questions
### Handle posits when generation already started
### Handle generation message before receiving started posit message


## Features
- subscribe for posit instead of forwarding from spawner

## misc



for signatures, we should wait for the requests to make it in, then create the SignatureTask, so posits should be sitting idle until we index the requests and it makes into the `SignQueue`. Rework the current creation of `SignatureTask` such that only after receiving a `SignRequest` can we create a `SignatureTask`. This doesn't mean to create the `SignatureTask` immediately after getting a `SignRequest` but rather that we can. This is because we require the `PresignatureId`. If we are the proposer, then this is determined by us, but otherwise we need to wait for the proposer to propose one through posits. So spawner should have pending posits for the sign request, then upon sign request ready, can process any posit that depend on those requests.

We should have a mapping of `(SignId, PresignatureId)` to Posit, such that we can forward


## Flow

TripleTask:

run
- recv posit w/ expiration
- start
- generate



## Tasks

- get rid of self.id == id and make it so our posit will always have our id.
- remove need for option of posit
- need to check if the unit test for posits still make any sense

## Remove internal option of posit

posit propose => propose action => deliberate posit

handle the logic for all incoming deliberate posits without Posits manager:



proposer:
- propose

deliberator:
- recv(propose), then deliberate


dependencies:
- pre task creation
  - check if task is ongoing
- post task creation
  - pending triple/presignature generation

```rs
tasks.handle(posit)


// we need a task map where we handle the logic for all incoming posits
struct ProtocolTasks<Id, Value: ProtocolTask> {
    tasks: JoinMap<Id>
}

trait ProtocolTask {
    const
    fn run()
}
```
propose => Protocol::deliberate

## Research

I want to get rid of `active: Option<ActivePosit<Id, S>>,` inside `Posit` and just put all the fields inside `Posit`. `Posit` creation would then be done with either `Posit::propose` or `Posit::deliberate`. This would mean that each task (`TripleTask`, `PresignatureTask`, `SignatureTask`) would now have to change how they interact with it. I am not sure how to go about handling `Propose` message as it would be pretty unclean the `act` not handle it, and the spawners would end up just listening for it specifically so it can call `Posit::deliberate` to create the `Posit`.  It ends up with two separate places to handle `PositAction`s. What's a better way of handling this?

## Task Deliberator/Proposer code path

instead of waiting for the new task to handle a new posit, let's have a codepath for newly posits if they don't exist as tasks yet. Such that this newly spawned task would immediately check for the positaction we received and whether it makes sense or not. For instance, `PositAction::propose` would make sense to have this task be immediately be a deliberator instead of the initiate action determining this.

So we'd have something like `{Triple, Presignature, Signature}Task` have two separate code paths for spawning themselves: `*Task::spawn_proposer` and `*Task::spawn_deliberator`.


## New task state

instead of having each posit be contained, when in generate phase, we should not have it stored anymore since we don't need it.



### Further refacotring later
```
ProtocolMessage {
    Propose,
    Start(participants),
    Message(message)
    Complete(result)
}
```