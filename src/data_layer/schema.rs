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
    client_auth (id) {
        id -> Nullable<Integer>,
        access_token -> Text,
        device_id -> Text,
    }
}

diesel::table! {
    ln_addresses (id) {
        id -> Nullable<Integer>,
        matrix_id -> Text,
        ln_address -> Text,
        lnurl -> Text,
        date_created -> Text,
    }
}

diesel::table! {
    matrix_store (id) {
        id -> Nullable<Integer>,
        state -> Binary,
        crypto -> Binary,
    }
}

diesel::table! {
    dm_rooms (matrix_id) {
        matrix_id -> Text,
        room_id -> Text,
    }
}
