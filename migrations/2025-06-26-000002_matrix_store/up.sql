CREATE TABLE matrix_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state BLOB NOT NULL,
    crypto BLOB NOT NULL
);
INSERT INTO matrix_store (id, state, crypto) VALUES (1, X'', X'');
