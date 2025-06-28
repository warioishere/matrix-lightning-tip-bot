// @generated automatically by Diesel CLI.

diesel::table! {
    client_auth (id) {
        id -> Nullable<Integer>,
        access_token -> Text,
        device_id -> Text,
    }
}

diesel::table! {
    dm_rooms (matrix_id) {
        matrix_id -> Nullable<Text>,
        room_id -> Text,
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
    matrix_id_2_lnbits_id (matrix_id) {
        matrix_id -> Text,
        lnbits_id -> Text,
        lnbits_admin -> Text,
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

diesel::allow_tables_to_appear_in_same_query!(
    client_auth,
    dm_rooms,
    ln_addresses,
    matrix_id_2_lnbits_id,
    matrix_store,
);
