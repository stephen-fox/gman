# gman

A manual page generator and viewer for Go packages.

Please note that this code is very ugly. I am not proud of it, but it
gets the job done (sort of). I originally created it to improve the
experience of developing in a non-graphical environment. I also wanted
to avoid emacs' documentation display shortcomings and not rely on a web
browser (I am not a fan of that trend in Go or Rust).

## Features

- Generate manual pages for Go packages based on their Go docs
- Specify documentation for specific OS and CPU architectures using
  environment variables or arguments
- Caches manual pages for offline use in `~/.gman`
- No external Go dependencies (though it requires `go` and `man`)

## Requirements

- `go` (for documentation generations)
- `man` / `less` (for viewing the manual pages)

## Installation

```sh
go install gitlab.com/stephen-fox/gman@latest
```

## Usage

```sh
gman [options] GO-PACKAGE-ID
```

## Examples

Generate and view the "crypto/tls" library manual:

```console
$ gman crypto/tls
```

Generate and view the manual for "golang.org/x/sys/unix" for FreeBSD:

```console
$ gman -s freebsd golang.org/x/sys/unix
```

Generate and view the manual for v0.4.0 of "golang.org/x/crypto/ssh":

```console
$ gman golang.org/x/crypto/ssh@v0.4.0
```

Generate the manual for the "syscall" library for OpenBSD and exit:

```console
$ gman -G -s openbsd syscall
```
