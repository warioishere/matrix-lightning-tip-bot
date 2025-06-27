mod models;
mod schema;

pub mod data_layer {

    use diesel::prelude::*;
    use diesel::SelectableHelper;

    use crate::config::config::Config;
    pub  use crate::data_layer::models::{
        LNBitsId, MatrixId2LNBitsId, NewMatrixId2LNBitsId,
        LnAddress, NewLnAddress, MatrixStore, NewMatrixStore,
    };
    use crate::data_layer::schema;

    use schema::matrix_id_2_lnbits_id::dsl::*;
    use schema::ln_addresses::dsl as ln_addresses_dsl;
    use schema::matrix_store::dsl as matrix_store_dsl;

    #[derive(Clone)]
    pub struct DataLayer {
        database_url: String
    }

    impl DataLayer {
        pub fn new(config: &Config) -> DataLayer {
            DataLayer {
                database_url: config.database_url.clone()
            }
        }

        fn establish_connection(&self) -> SqliteConnection {
            SqliteConnection::establish(&self.database_url).unwrap_or_else(|_| panic!("Error connecting to {}", self.database_url))
        }

        pub fn lnbits_id_exists_for_matrix_id(&self, matrix_id_: &str) -> bool {
            let mut connection = self.establish_connection();
            let result = matrix_id_2_lnbits_id.find(matrix_id_)
                                                  .load::<MatrixId2LNBitsId>(&mut connection)
                                                  .expect("Error looking up stuff");
            result.len() > 0
        }

        pub fn insert_matrix_id_2_lnbits_id(&self, new_matrix_id_2_lnbits_id: NewMatrixId2LNBitsId ) {

            let mut connection = self.establish_connection();
            diesel::insert_into(schema::matrix_id_2_lnbits_id::table)
                   .values(&new_matrix_id_2_lnbits_id)
                   .execute(&mut connection)
                   .expect("Error saving new matrix_id_2_ln_bits_id");
        }

        pub fn lnbits_id_for_matrix_id(&self, matrix_id_: &str) -> LNBitsId {
            let mut connection = self.establish_connection();
            let mut result = matrix_id_2_lnbits_id.find(matrix_id_)
                                                  .load::<MatrixId2LNBitsId>(&mut connection)
                                                  .expect("Error looking up stuff");
            result.remove(0).get_lnbits_id()
        }

        pub fn insert_ln_address(&self, new_ln_address: NewLnAddress) {
            let mut connection = self.establish_connection();
            diesel::insert_into(schema::ln_addresses::table)
                .values(&new_ln_address)
                .execute(&mut connection)
                .expect("Error saving ln address");
        }

        pub fn ln_addresses_for_matrix_id(&self, matrix_id_: &str) -> Vec<LnAddress> {
            let mut connection = self.establish_connection();
            ln_addresses_dsl::ln_addresses
                .filter(ln_addresses_dsl::matrix_id.eq(matrix_id_))
                .select(LnAddress::as_select())
                .load::<LnAddress>(&mut connection)
                .expect("Error loading ln addresses")
        }

        pub fn load_matrix_store(&self) -> Option<(Vec<u8>, Vec<u8>)> {
            let mut connection = self.establish_connection();
            matrix_store_dsl::matrix_store
                .filter(matrix_store_dsl::id.eq(1))
                .select(MatrixStore::as_select())
                .load::<MatrixStore>(&mut connection)
                .ok()
                .and_then(|mut v| v.pop())
                .map(|r| (r.state, r.crypto))
        }

        pub fn save_matrix_store(&self, state: &[u8], crypto: &[u8]) {
            let mut connection = self.establish_connection();
            let new_store = NewMatrixStore { id: 1, state, crypto };
            diesel::replace_into(schema::matrix_store::table)
                .values(&new_store)
                .execute(&mut connection)
                .expect("Error saving matrix store");
        }
    }
}

