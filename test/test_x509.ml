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
  let pp_public_key fmt _ = Format.fprintf fmt "%s" "a public key"
  let pp_private_key fmt _ = Format.fprintf fmt "%s" "a private key"
  let equal_public_key (a : public_key) (b : public_key) : bool =
    match a, b with
    | `RSA a, `RSA b -> Nocrypto.Rsa.(Z.equal a.e b.e && Z.equal a.n b.n)
    | `EC_pub _, `EC_pub _ -> Crowbar.fail "somehow got two EC_pub public keys?"
    | `RSA _, `EC_pub _ | `EC_pub _, `RSA _ -> false
  (* this definition of equal_private_key is not correct, but it's probably sufficient
     to keep us from confusing two private keys *)
  let equal_private_key (`RSA a) (`RSA b) = Nocrypto.Rsa.(Z.equal a.e b.e && Z.equal a.n b.n)
  
  (* no printers nor equality tests exposed for `t`.  The best we
     can get out of X509 is the associated S-expression :/ *)
  type t = X509.t
  let pp fmt t = Format.fprintf fmt "%s" (X509.sexp_of_t t |> Sexplib.Sexp.to_string_hum)
  let equal a b = 0 = (Sexplib.Sexp.compare (X509.sexp_of_t a) (X509.sexp_of_t b))

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
  end
  module Validation = struct
    type fingerprint_validation_error = [%import: X509.Validation.fingerprint_validation_error] [@@deriving show, eq]
    type leaf_validation_error = [%import: X509.Validation.leaf_validation_error] [@@deriving show, eq]
    type chain_validation_error = [%import: X509.Validation.chain_validation_error] [@@deriving show, eq]
    type chain_error = [%import: X509.Validation.chain_error] [@@deriving show, eq]
    type validation_error = [%import: X509.Validation.validation_error] [@@deriving show, eq]
    type result = [%import: X509.Validation.result] [@@deriving show, eq]
  end
end

let () =
  let seed = Cstruct.of_string "yolocryptolol" in
  (* we need to tell nocrypto to use a constant seed *)
  let g = Nocrypto.Rng.generator in
  g := Nocrypto.Rng.(create ~seed (module Generators.Fortuna));
  let request_of_key key = Crowbar.(map [Crowbar_X509.distinguished_name_to_crowbar;
                                     list Crowbar_X509.CA.request_extensions_to_crowbar;
                                     hash_to_crowbar] (fun dn extensions digest ->
      X509.CA.request dn ~extensions ~digest (`RSA key))) in
  let ca_ify ~key csr =
    let name = X509.CA.((info csr).subject) in
    let valid_from = Ptime.min in
    let valid_until = Ptime.max in 
    let extensions = [(true, `Basic_constraints (true, None)); (true, `Key_usage [`Key_cert_sign])] in
    X509.CA.sign ~extensions ~valid_from ~valid_until csr (`RSA key) name
  in
  Crowbar.(add_test ~name:"non-CA selfsigned certs aren't CAs"
             [request_of_key Keys.csr_priv] @@ fun csr ->
           let name = X509.CA.((info csr).subject) in
           let valid_from = Ptime.min in
           let valid_until = Ptime.max in 
           let cert = X509.CA.sign ~valid_from ~valid_until csr (`RSA Keys.csr_priv) name in
           (* since we didn't pass any extensions when self-signing, this should always fail with
              CAInvalidExtensions *)
           let expected_failure : X509.Validation.ca_error = (`CAInvalidExtensions cert) in
           check_eq (`Error expected_failure) (X509.Validation.valid_ca cert)
          );

  Crowbar.(add_test ~name:"selfsigned certs with correct extensions are CAs"
             [request_of_key Keys.ca_priv] @@ fun csr ->
           let cert = ca_ify ~key:Keys.ca_priv csr in
           check_eq `Ok @@ X509.Validation.valid_ca cert
          );
  Crowbar.(add_test ~name:"CAs can sign certs and be valid for them"
             [request_of_key Keys.ca_priv; request_of_key Keys.csr_priv] @@
           fun ca csr ->
           let valid_from = Ptime.min in
           let valid_until = Ptime.max in
           let issuer = X509.CA.((info ca).subject) in
           let ca_cert = ca_ify ~key:Keys.ca_priv ca in
           let signed_cert = X509.CA.sign csr ~valid_from ~valid_until (`RSA Keys.ca_priv)
               issuer in
           (* the entire chain of trust is cert -> ca_cert *)
           (* first element of verify_chain_of_trust is "the actual certificate chain",
              so just the cert we generated and are checking;
              second element of the tuple is the trust anchor (ca_cert) *)
           let expected_success : X509.Validation.result =
             `Ok (Some ([signed_cert], ca_cert))
           in
           check_eq
             ~eq:Crowbar_X509.Validation.equal_result
             ~pp:Crowbar_X509.Validation.pp_result expected_success @@
             X509.Validation.verify_chain_of_trust ~anchors:[ca_cert] [signed_cert]
          )
