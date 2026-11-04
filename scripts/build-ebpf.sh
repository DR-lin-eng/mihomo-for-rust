#!/bin/sh
set -eu
# Run in Linux with clang, LLVM and libbpf development headers.
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/rust/crates/mihomo-ebpf/bpf"}
mkdir -p "$output_dir"
architecture_include="/usr/include/$(cc -dumpmachine)"
for byte_order in bpfel bpfeb; do
  for program in mihomo direct; do
    clang -target "$byte_order" -O2 -g -Wall -Werror -fdebug-prefix-map="$repo_dir"=. \
      -I "$architecture_include" -c "$repo_dir/rust/crates/mihomo-ebpf/bpf/$program.c" \
      -o "$output_dir/$program.$byte_order.o"
    llvm-strip -g "$output_dir/$program.$byte_order.o"
  done
done
