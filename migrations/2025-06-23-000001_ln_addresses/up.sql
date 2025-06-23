CREATE TABLE "ln_addresses" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    matrix_id TEXT NOT NULL,
    ln_address TEXT NOT NULL,
    lnurl TEXT NOT NULL,
    date_created TEXT NOT NULL
);
