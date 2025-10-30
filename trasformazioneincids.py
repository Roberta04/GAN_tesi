import pandas as pd

# lettura csv
df = pd.read_csv("traffico_unito_labeled2.csv")

# Colonne estratte con cicflowmeter
colonne_originali = [
    "src_ip","dst_ip","src_port",
    "pkt_size_avg", "pkt_len_std", "pkt_len_var", "pkt_len_mean",
    "totlen_bwd_pkts", "subflow_bwd_byts", "dst_port", "bwd_seg_size_avg",
    "bwd_pkt_len_mean", "init_fwd_win_byts", "subflow_fwd_byts", "totlen_fwd_pkts",
    "pkt_len_max", "bwd_pkt_len_max", "init_bwd_win_byts", "fwd_pkt_len_max",
    "fwd_pkt_len_mean", "fwd_seg_size_avg", "flow_iat_max", "flow_byts_s", "Label"
]

colonne_dataset_cicids = [
    "src_ip","dst_ip","src_port",
    "AveragePacketSize", "PacketLengthStd", "PacketLengthVariance", "PacketLengthMean",
    "TotalLengthOfBwdPackets", "SubflowBwdBytes", "DestinationPort", "AvgBwdSegmentSize",
    "BwdPacketLengthMean", "InitWinBytesFwd", "SubflowFwdBytes", "TotalLengthOfFwdPackets",
    "MaxPacketLength", "BwdPacketLengthMax", "InitWinBytesBwd", "FwdPacketLengthMax",
    "FwdPacketLengthMean", "AvgFwdSegmentSize", "FlowIATMax", "FlowBytesPerSecond", "target"
]


df_modificato = df[colonne_originali]

df_modificato.columns = colonne_dataset_cicids

df_modificato.to_csv("dataset_ack_tserver_cids.csv", index=False)
