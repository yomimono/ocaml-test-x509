module Asn = struct
  include Asn
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

module Crowbar_X509 = struct
  open X509
  type key_type' = [%import: X509.key_type ] [@@deriving crowbar]
  let key_type_to_crowbar = key_type'_to_crowbar
  type host' = [%import: X509.host ] [@@deriving crowbar]
  let host_to_crowbar = host'_to_crowbar
  type component' = [%import: X509.component ] [@@deriving crowbar]
  let component_to_crowbar = component'_to_crowbar
  let distinguished_name_to_crowbar = Crowbar.list component_to_crowbar

  (* keypairs are special -- always use the precomputed ones *)
  let public_key_to_crowbar : X509.public_key Crowbar.gen =
    Crowbar.const X509.(`RSA (Nocrypto.Rsa.pub_of_priv Keys.priv))
  let private_key_to_crowbar : X509.private_key Crowbar.gen =
    Crowbar.const X509.(`RSA Keys.priv)

  module Extension = struct
    include X509.Extension
    type key_usage' = [%import: X509.Extension.key_usage] [@@deriving crowbar]
    let key_usage_to_crowbar = key_usage'_to_crowbar
    type extended_key_usage' = [%import: X509.Extension.extended_key_usage]
    [@@deriving crowbar]
    let extended_key_usage_to_crowbar = extended_key_usage'_to_crowbar
    type general_name' = [%import: X509.Extension.general_name] [@@deriving crowbar]
    let general_name_to_crowbar = general_name'_to_crowbar
    (* our authority_keys will always have None as their third element 
       to (cowardly) avoid Z.to_crowbar *)
    let authority_key_id_to_crowbar =
        Crowbar.(map [option Cstruct.to_crowbar; list general_name_to_crowbar]
		    (fun a b -> a, b, None))
    type priv_key_usage_period' = [%import: X509.Extension.priv_key_usage_period]
       [@@deriving crowbar]
    let priv_key_usage_period_to_crowbar = priv_key_usage_period'_to_crowbar
    type name_constraint' = [%import: X509.Extension.name_constraint] [@@deriving crowbar]
    let name_constraint_to_crowbar = name_constraint'_to_crowbar
    type policy' = [%import: X509.Extension.policy] [@@deriving crowbar]
    let policy_to_crowbar = policy'_to_crowbar
    type reason' = [%import: X509.Extension.reason] [@@deriving crowbar]
    let reason_to_crowbar = reason'_to_crowbar
    type reason_code' = [%import: X509.Extension.reason_code] [@@deriving crowbar]
    let reason_code_to_crowbar = reason_code'_to_crowbar
    type distribution_point_name' = [%import: X509.Extension.distribution_point_name] [@@deriving crowbar]
    let distribution_point_name_to_crowbar = distribution_point_name'_to_crowbar
    type distribution_point' = [%import: X509.Extension.distribution_point] [@@deriving crowbar]
    let distribution_point_to_crowbar = distribution_point'_to_crowbar
    type t' = [%import: X509.Extension.t] [@@deriving crowbar]
    let to_crowbar = t'_to_crowbar
  end
end

let () =
   Crowbar.(add_test ~name:"component is derivable" [Crowbar_X509.component_to_crowbar]
              (fun t -> check true));
   Crowbar.(add_test ~name:"extensions are derivable" [Crowbar_X509.Extension.to_crowbar]
              (fun t -> check true));
  ()
