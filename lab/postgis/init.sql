CREATE EXTENSION IF NOT EXISTS postgis;
CREATE SCHEMA geoscan;

CREATE TABLE geoscan.items (
    id INTEGER PRIMARY KEY,
    json_data TEXT NOT NULL,
    geom geometry(Point, 4326) NOT NULL
);

INSERT INTO geoscan.items (id, json_data, geom) VALUES
    (1, '{"a":["x"]}', ST_SetSRID(ST_MakePoint(77.59, 12.97), 4326)),
    (2, '{"a":["other"]}', ST_SetSRID(ST_MakePoint(72.88, 19.08), 4326));

CREATE ROLE geoscan_reader LOGIN PASSWORD 'geoscan-demo-readonly'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE geoscan_demo TO geoscan_reader;
GRANT USAGE ON SCHEMA public, geoscan TO geoscan_reader;
GRANT SELECT ON geoscan.items TO geoscan_reader;
ALTER ROLE geoscan_reader SET default_transaction_read_only = on;
