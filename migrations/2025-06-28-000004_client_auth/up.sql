CREATE TABLE client_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    access_token TEXT NOT NULL,
    device_id TEXT NOT NULL
);
INSERT INTO client_auth (id, access_token, device_id) VALUES (1, '', 'ASDEVICE');
