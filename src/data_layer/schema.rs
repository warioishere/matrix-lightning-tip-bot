// @generated automatically by Diesel CLI.

diesel::table! {
    matrix_id_2_lnbits_id (matrix_id) {
        matrix_id -> Text,
        lnbits_id -> Text,
        lnbits_admin -> Text,
        date_created -> Text,
    }
}

diesel::table! {
    ln_addresses (id) {
        id -> Integer,
        matrix_id -> Text,
        ln_address -> Text,
        lnurl -> Text,
        date_created -> Text,
    }
}
