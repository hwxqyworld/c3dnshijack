idf_component_register(
    SRCS "dnshij.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES server_cert.pem server_key.pem
)

