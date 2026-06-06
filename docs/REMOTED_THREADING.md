# ossec-remoted threading model

This document describes the threaded listener model introduced in the OSSEC 4.1
fork-to-threads migration for `ossec-remoted`.

## Architecture

- **One process** replaces the previous fork-per-`<remote>`-connection model.
- **Main thread** binds all listeners before `setuid`, then starts one detached
  worker thread per configured `<remote>` entry.
- Each listener thread runs `HandleRemote()` for secure UDP, syslog UDP, or
  syslog TCP.

```text
main: bind listeners -> setuid -> CreateThread per listener -> wait for shutdown
  |
  +-- secure listener: HandleSecure() [recv + AR_Forward + wait_for_msgs threads]
  +-- syslog UDP:      HandleSyslog()  [single select/recvfrom loop]
  +-- syslog TCP:      HandleSyslogTCP() [accept loop + thread pool per client]
```

## Privilege separation

All listener sockets are bound in the main thread **before** dropping UID.
This ensures low ports (1514, 514) bind correctly under a single `setuid`.

## Limits (`internal_options.conf`)

| Option | Meaning |
|--------|---------|
| `remoted.syslog_tcp_worker_pool` | Syslog TCP worker threads (default 16, max 64). |
| `remoted.syslog_tcp_max_tasks` | Max queued + active syslog TCP client handlers (default 64). |
| `ossec.thread_stack_size` | Worker thread stack size in KiB (default 2048). |

Configuration also enforces at most **one** `<connection>secure</connection>` and
**16** total listeners (`REMOTE_LISTENERS_MAX`).

## Shared state assumptions

Global `keys` is loaded only in the secure listener thread. The single-secure
constraint is required because `send_msg()`, AR forward, and the manager share
one keystore and `sendmsg_mutex` across threads.

Syslog listeners use per-listener `m_queue` with `mq_mutex`; syslog TCP client
handlers run in a bounded `thread_pool` per listener.

## Graceful shutdown

On `SIGINT` / `SIGTERM` / `SIGQUIT`:

1. First signal sets `remoted_shutting_down` and closes listener sockets (unblocks
   `select()` in listener threads).
2. Syslog TCP stops accepting; main waits up to **60 seconds** for the syslog TCP
   thread pool to drain.
3. Second signal forces immediate exit (legacy behavior).

## Staging checks

| Scenario | Expected |
|----------|----------|
| Secure + syslog UDP + syslog TCP configured | All listeners active in one PID |
| Syslog TCP connection burst | Pool backpressure; excess connections dropped with WARN |
| `kill -TERM` remoted during TCP client handling | No new accepts; exit within 60s or timeout warn |
