import pandas as pd

# Caricamento CSV
packets_csv = "traffico_unito.csv"
df_packets = pd.read_csv(packets_csv)

# Conversione del protocollo da stringa a numerico
protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
df_packets["protocol"] = df_packets["protocol"].map(protocol_map).fillna(df_packets["protocol"])

# One-Hot Encoding della colonna "flag"
df_packets = pd.get_dummies(df_packets, columns=["flag"], prefix="flag")

# Creazione del flow_id
df_packets["flow_id"] = (
    df_packets["src_ip"].astype(str) + "_" +
    df_packets["dst_ip"].astype(str) + "_" +
    df_packets["src_port"].astype(str) + "_" +
    df_packets["dst_port"].astype(str) + "_" +
    df_packets["protocol"].astype(str)
)

# Seleziona solo le colonne numeriche (escludendo porte e protocollo)
exclude_cols = ["src_port", "dst_port", "protocol"]
numeric_cols = [col for col in df_packets.select_dtypes(include=["number"]).columns if col not in exclude_cols]

# Media delle feature numeriche per flow_id
df_mean = df_packets.groupby("flow_id")[numeric_cols].mean().reset_index()

# Campi fissi (uno per flusso)
df_meta = df_packets.groupby("flow_id")[["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]].first().reset_index()

# Numero di pacchetti
df_count = df_packets.groupby("flow_id").size().reset_index(name="num_packets")

# Merge finale
df_flows = (
    df_mean
    .merge(df_meta, on="flow_id")
    .merge(df_count, on="flow_id")
)

# Ordina le colonne come preferisci
ordered_cols = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "num_packets",
    "duration", "src_bytes", "dst_bytes", "same_srv_rate", "diff_srv_rate",
    "dst_host_srv_count", "dst_host_same_srv_rate", "logged_in", "dst_host_serror_rate",
    "dst_host_diff_srv_rate", "dst_host_srv_serror_rate", "serror_rate", "srv_serror_rate",
    "count", "service_http", "dst_host_srv_diff_host_rate", "dst_host_count",
    "dst_host_same_src_port_rate", "service_private", "srv_diff_host_rate",
    "srv_count", "dst_host_srv_rerror_rate", "service_domain_u"
]

# Mantieni solo le colonne che esistono nel dataframe (nel caso qualcuna manchi)
ordered_cols = [c for c in ordered_cols if c in df_flows.columns]

# Riordina
df_flows = df_flows[ordered_cols]


# Salva in CSV
df_flows.to_csv("flows_with_features.csv", index=False)

print("✅ Dataset dei flussi (media + one-hot flag) salvato in flows_with_mean_features.csv")
