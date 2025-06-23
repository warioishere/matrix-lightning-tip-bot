use crate::data_layer::schema::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Queryable)]
pub struct MatrixId2LNBitsId {
    pub matrix_id: String,
    pub lnbits_id: String,
    pub lnbits_admin: String,
    pub date_created: String,
}

impl MatrixId2LNBitsId {
    pub fn get_lnbits_id(&self) -> LNBitsId {
        LNBitsId::new(self.lnbits_id.as_str())
    }
}

#[derive(Insertable)]
#[diesel(table_name = matrix_id_2_lnbits_id)]
pub struct NewMatrixId2LNBitsId<'a> {
    pub matrix_id: &'a str,
    pub lnbits_id: &'a str,
    pub lnbits_admin: &'a str,
    pub date_created: &'a str,
}

impl NewMatrixId2LNBitsId<'_> {
    pub fn new<'a>(matrix_id: &'a str,
                   lnbits_id: &'a str,
                   lnbits_admin: &'a str,
                   date_created: &'a str) -> NewMatrixId2LNBitsId<'a> {
        NewMatrixId2LNBitsId {
            matrix_id,
            lnbits_id,
            lnbits_admin,
            date_created
        }
    }
}

pub struct LNBitsId {
    pub lnbits_id: String,
}

impl LNBitsId {
    pub fn new(lnbits_id: &str) -> LNBitsId {
        LNBitsId {
            lnbits_id: String::from(lnbits_id)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = ln_addresses)]
pub struct LnAddress {
    pub id: Option<i32>,
    pub matrix_id: String,
    pub ln_address: String,
    pub lnurl: String,
    pub date_created: String,
}

#[derive(Insertable)]
#[diesel(table_name = ln_addresses)]
pub struct NewLnAddress<'a> {
    pub matrix_id: &'a str,
    pub ln_address: &'a str,
    pub lnurl: &'a str,
    pub date_created: &'a str,
}

impl NewLnAddress<'_> {
    pub fn new<'a>(matrix_id: &'a str,
                   ln_address: &'a str,
                   lnurl: &'a str,
                   date_created: &'a str) -> NewLnAddress<'a> {
        NewLnAddress { matrix_id, ln_address, lnurl, date_created }
    }
}
