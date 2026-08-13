# Orchestrator role

Read this to run the orchestrator session in the multi-session workflow. The companion
role is [ROLE-IMPLEMENTER.md](ROLE-IMPLEMENTER.md), and the full flow diagram lives
there. This document defines the workflow terms: task, brief, partition, in-flight,
prep, slot, land, and board.

## The role

**The orchestrator sequences work and owns TODO.md — it never reads the
implementation.** It knows the task list, the discussions with the user, each task's
state, and each task's partition. It does not read diffs, source files, or test
output. File paths are state, not implementation: the partition map is the one code
fact this role holds. At session start, read TODO.md and the board — nothing else.
The user opens every implementer session: the orchestrator briefs sessions and never
launches them.

## The board

**The board holds the active state, so a compacted or restarted session recovers
it.** The board lives at `BOARD.local.md` in the repository root, untracked (one
`.gitignore` line). Update it on every state change. Two lines per task: the state
line, then the partition.

```
<task-slug>  <branch>  <session name [ref]>  <state>
  owns: <files and directories this task touches>
```

The states are `queued`, `briefed`, `ready`, `rebasing`, `prepped`, `landing`,
`landed`, and `blocked`. A task is `queued` while it lives only in TODO.md. Design,
implementation, and review loops all happen inside `briefed`: the implementer reports
no intermediate step. The in-flight set is every task in `rebasing`, `prepped`, or
`landing`.

## Brief an implementer

**A brief carries the goal, the constraints, and the partition — never a design.**
When the user opens a session for a task:

1. Read the task's TODO.md entry.
2. Assign the branch name `agent/<task-slug>` and the partition: the files the task
   owns. If the partition overlaps another active task, ask the user to sequence the
   two tasks or to split the files.
3. Find the new session with ListAgents. Address it as `name [ref]`.
4. Send one BRIEF message: the task, the TODO.md entry text, the constraints from
   discussion, the branch name, the partition, what the other active tasks own, and a
   pointer to ROLE-IMPLEMENTER.md.
5. Set the board state to `briefed`.

## Layer 1: rebase grants, concurrent

**Branches rebase concurrently only when they are pairwise disjoint — then no land
can invalidate another branch's rebase work.** Everything lands through the queue,
and only prepped branches enter the queue. So whatever lands while a disjoint branch
rebases cannot conflict with it, and its catch-up rebase under the slot stays
trivial. On a READY message:

1. Replace the task's partition on the board with the touched files that READY
   reports.
2. Compare those files with every in-flight task. If they are disjoint, send REBASE
   with the current main tip and the in-flight list, and set the state to `rebasing`.
   If they overlap, tell the implementer which branch it waits on, and send REBASE
   when that branch lands.
3. On PREPPED, set the state to `prepped`.

Two branches that overlap each other serialize their expensive rebases by design. The
second redoes its resolution against the result of the first — no queue removes that
cost, because it is the conflict itself. Surface the dependency to the user, who can
reorder the tasks.

## Layer 2: the land queue, serial

**One slot exists, and main only ever moves under it.** To land is to fast-forward
main to the prepped branch and release the slot.

1. PREPPED tasks enqueue in arrival order. The user can reorder the queue.
2. When no task is `landing`, send SLOT with the current main tip to the head of the
   queue. Set the state to `landing`.
3. On LANDED, set the state to `landed` and grant the next slot.

Never grant a second slot while one is out. If a slot stalls, ask the user whether
the holder keeps it.

## After a land

**TODO.md changes on main only, and only the orchestrator writes it.** A branch that
edits TODO.md conflicts with every other branch, so this rule removes the one
guaranteed conflict. On a LANDED message:

1. Discuss the reported follow-ups with the user: execute now, or track in TODO.md.
2. Edit TODO.md: remove the landed entry, add the tracked follow-ups under their
   sections.
3. Commit on main: `docs(todo): <description>`. One commit per land batches every
   edit into one permission prompt.
4. A follow-up chosen for execution becomes a new task: the user opens a session, and
   the cycle restarts.

## Message protocol

**Seven message types carry the whole workflow.** Both roles batch everything they
have to say into their next protocol message.

| Message | Direction | Content |
|---|---|---|
| BRIEF | orchestrator → implementer | task, TODO.md entry, constraints, branch name, partition |
| READY | implementer → orchestrator | branch, touched files, one-line status |
| REBASE | orchestrator → implementer | current main tip, in-flight list — or the branch it waits on |
| PREPPED | implementer → orchestrator | branch, suite result |
| SLOT | orchestrator → implementer | current main tip |
| LANDED | implementer → orchestrator | new main tip, follow-ups, one-line status |
| BLOCKED | implementer → orchestrator | reason, and what unparks it |

## Permission economy

**The orchestrator runs on reads, messages, board edits, and TODO.md commits —
nothing else.** ListAgents, SendMessage, and local reads run without a prompt. If
board edits prompt, allowlist edits to `BOARD.local.md` in
`.claude/settings.local.json`. The TODO.md commit stays behind a prompt on purpose:
it is the one mutation of main this role performs.
