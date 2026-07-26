# Central Design Decisions

There are a couple of central design decisions that have voluntarily been made.
This document explains the reasoning behind these decisions.

## Single-threaded async runtime

A single-threaded async runtime (tokio / current_thread) is used.
This is to avoid true parallelism as much as possible to reduce the attack surface.

Note that single threaded tokio runtime can still spawn threads for blocking operations.
But we try to avoid blocking operations as much as possible.

## File I/O is synchronous

`tokio::fs` async I/O is not used for file I/O.
Instead synchronous `std::fs` file I/O is used.
Tokio's async file I/O requires threads, which we want to avoid to reduce true parallelism.
