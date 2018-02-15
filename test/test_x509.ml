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

type hash = [%import: Nocrypto.Hash.hash] [@@deriving crowbar, show, eq]

module Crowbar_X509 = struct
  type key_type = [%import: X509.key_type ] [@@deriving crowbar, show, eq]
  type host = [%import: X509.host ] [@@deriving crowbar, show, eq]
  type component = [%import: X509.component] [@@deriving crowbar, show, eq]
  type distinguished_name = [%import: X509.distinguished_name ] [@@deriving crowbar, show, eq]

  type public_key = X509.public_key
  type private_key = X509.private_key

  (* keypairs are special -- always use the precomputed ones *)
  let public_key_to_crowbar : X509.public_key Crowbar.gen =
    Crowbar.const X509.(`RSA (Nocrypto.Rsa.pub_of_priv Keys.csr_priv))
  let private_key_to_crowbar : X509.private_key Crowbar.gen =
    Crowbar.const X509.(`RSA Keys.csr_priv)
  let pp_public_key fmt _ = Format.fprintf fmt "%s" "the public key"
  let pp_private_key fmt _ = Format.fprintf fmt "%s" "the private key"
  let equal_public_key _ _ = true
  let equal_private_key _ _ = true

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
  module CA = struct
    type request_extensions = [%import: X509.CA.request_extensions] [@@deriving crowbar, show, eq]
    type request_info = [%import: X509.CA.request_info] [@@deriving crowbar, show, eq]
    let signing_request_to_crowbar = Crowbar.(map [distinguished_name_to_crowbar;
                                                  list request_extensions_to_crowbar;
                                                  hash_to_crowbar;
                                                  private_key_to_crowbar] (fun dn extensions digest key ->
        X509.CA.request dn ~extensions ~digest key))
  end
end

let () =
  let seed = Cstruct.of_string "yolocryptolol" in
  (* we need to tell nocrypto to use a constant seed *)
  let g = Nocrypto.Rng.generator in
  g := Nocrypto.Rng.(create ~seed (module Generators.Fortuna));
  Crowbar.(add_test ~name:"ASN1 roundtrip" [Crowbar_X509.CA.signing_request_to_crowbar]
  (fun csr ->
      let aux asn1 =
	match X509.Encoding.parse_signing_request asn1 with
        | None -> Format.asprintf "%a\n%!" Crowbar_X509.CA.pp_request_info @@
                  X509.CA.info csr |> Crowbar.fail
        | Some read_csr ->  read_csr
      in
      let read_csr = aux @@ X509.Encoding.cs_of_signing_request csr in
      (* this test fails a LOT because the extensions get reordered in their roundtrip.
         According to RFC3280 sec 4.1.2.9 "Extensions", "If present, this field
         is a SEQUENCE of one or more certificate extensions." *)
      (* RFC5280 agrees, tagging "Extensions ::= SEQUENCE SIZE (1..MAX OF Extension). *)
      Crowbar.check_eq ~pp:Crowbar_X509.CA.pp_request_info
	~eq:Crowbar_X509.CA.equal_request_info
        (X509.CA.info csr) (X509.CA.info @@ aux @@ X509.Encoding.cs_of_signing_request read_csr)
  ))
