module Asn = struct
  include Asn
  let pp_oid = Asn.OID.pp
  let equal_oid = Asn.OID.equal
  let oid_base_to_crowbar =
    (* OID bases are different depending on the leading integer.
       if the first number is 0 or 1, the second number is 0..39 inclusive;
       if the first number is 2, the second number is any nonnegative number. *)
    let early_edition =
      Crowbar.(map [choose [const 0; const 1]; range 40] Asn.OID.base)
    in
    let late_edition = Crowbar.(map [const 2; range max_int] Asn.OID.base) in
    Crowbar.(choose [early_edition; late_edition])

  let oid_to_crowbar = Crowbar.(map [oid_base_to_crowbar; list (range max_int)]
                                  Asn.OID.(<||))
end

module Cstruct = struct
  include Cstruct
  let pp fmt s = Format.fprintf fmt "%s" (Cstruct.to_string s)
  let to_crowbar = Crowbar.(map [bytes] Cstruct.of_string)
end

module Ptime = struct
  let succ = (+) 1
  (* lots of semantics in the right arguments to ptime, so define this stuff
     ourselves to hopefully cut down on the proportion of failed generations *)
  let date_to_crowbar = Crowbar.(map [range 10000;
    map [range 11] succ;
    map [range 30] succ]
    (fun y m d -> y, m, d))
  let tz_offset_to_crowbar = Crowbar.(map [range 7200] (fun x -> x - 3600))
  let time_to_crowbar = Crowbar.(map [range 23; range 59; range 60; tz_offset_to_crowbar]
    (fun h m s tz -> (h, m, s), tz))
  let to_crowbar = Crowbar.(map
    [date_to_crowbar; time_to_crowbar] (fun date time ->
    nonetheless @@ Ptime.of_date_time (date, time)))
  include Ptime
end

module Z = struct
  include Z
  let to_crowbar = Crowbar.(map [int64] Z.of_int64)
  let pp fmt z = Format.fprintf fmt "%s" @@ Z.to_string z
end

module Crowbar_X509 = struct
  type key_type = [%import: X509.key_type ] [@@deriving crowbar, show, eq]
  type host = [%import: X509.host ] [@@deriving crowbar, show, eq]
  type component = [%import: X509.component] [@@deriving crowbar, show, eq]
  type distinguished_name = [%import: X509.distinguished_name ] [@@deriving crowbar, show, eq]

  module Extension = struct
    type key_usage = [%import: X509.Extension.key_usage] [@@deriving crowbar, show, eq]
    type extended_key_usage = [%import: X509.Extension.extended_key_usage] [@@deriving crowbar, show, eq]
    type general_name = [%import: X509.Extension.general_name] [@@deriving crowbar, show, eq]
    type authority_key_id = [%import: X509.Extension.authority_key_id] [@@deriving crowbar, show, eq]
    type priv_key_usage_period = [%import: X509.Extension.priv_key_usage_period]
       [@@deriving crowbar, show, eq]
    type name_constraint = [%import: X509.Extension.name_constraint] [@@deriving crowbar, show, eq]
    type policy = [%import: X509.Extension.policy] [@@deriving crowbar, show, eq]
    type reason = [%import: X509.Extension.reason] [@@deriving crowbar, show, eq]
    type reason_code = [%import: X509.Extension.reason_code] [@@deriving crowbar, show, eq]
    type distribution_point_name = [%import: X509.Extension.distribution_point_name] [@@deriving crowbar, show, eq]
    type distribution_point = [%import: X509.Extension.distribution_point] [@@deriving crowbar, show, eq]
    type t = [%import: X509.Extension.t] [@@deriving crowbar, show, eq]
  end
end

let () =
  let seed = Cstruct.of_string "yolocryptolol" in
  let serial = Z.of_int 1234567890 in
  (* we need to tell nocrypto to use a constant seed *)
  let g = Nocrypto.Rng.generator in
  g := Nocrypto.Rng.(create ~seed (module Generators.Fortuna));
  let pinata_ca_dn = [`CN "BTC Pinata CA"] in
  let pinata_client_dn = [`CN "Pinata client"] in
  let ca_ify ~key csr =
    let name = X509.CA.((info csr).subject) in
    let valid_from = Ptime.min in
    let valid_until = Ptime.max in 
    let extensions = [(true, `Basic_constraints (true, None)); (true, `Key_usage [`Key_cert_sign])] in
    X509.CA.sign ~extensions ~valid_from ~valid_until csr (`RSA key) name
  in
  let csr = X509.CA.request pinata_client_dn (`RSA Keys.csr_priv) in
  let real_ca = ca_ify ~key:Keys.ca_priv @@ X509.(CA.request pinata_ca_dn (`RSA Keys.ca_priv)) in
  let valid_from, valid_until = Ptime.(min, max) in
  let pair gen1 gen2 = Crowbar.(map [gen1; gen2] @@ fun a b -> a, b) in
  let extensions = Crowbar.(pair bool Crowbar_X509.Extension.to_crowbar) in
  Crowbar.(add_test ~name:"no trust chain for cert signed by a rando, no matter \
how ridiculous they were about signing it"
             [list extensions] @@ fun extensions ->
           let signed_by_rando =
               X509.CA.sign csr ~valid_from ~valid_until ~digest:X509.(`SHA1) ~extensions ~serial
                 (`RSA Keys.rando_priv) pinata_ca_dn in
           let _expected_failure : X509.Validation.result =
             `Fail (`InvalidChain)
           in
           let is_failure = function | `Fail _ -> true | `Ok _ -> false in
           Format.printf "%s\n" (X509.sexp_of_t signed_by_rando |> Sexplib.Sexp.to_string_hum);
           check @@ is_failure @@
             X509.Validation.verify_chain_of_trust ~anchors:[real_ca] [signed_by_rando]
          )
