#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe ~readmes:[] ~licenses:[] ~change_logs:[] ~opams:[] "test_x509" @@ fun c -> Ok [
    Pkg.bin "test/test_x509";
  ]
