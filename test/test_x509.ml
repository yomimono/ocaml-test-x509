module type Certificate = [%import: (module X509)] [@@deriving crowbar]

let () =
   Crowbar.(add_test ~name:"t is derivable" [Certificate_to_crowbar.to_crowbar]
(fun t -> check true))
  ()
