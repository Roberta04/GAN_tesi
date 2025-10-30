import pandas as pd
import glob
import os

# Trova tutti i file CSV che iniziano con 'traffico'
csv_files = glob.glob("traffico*.csv")

if not csv_files:
    print("Nessun file trovato con il pattern 'traffico*.csv'.")
else:
    # Lista per contenere i DataFrame
    df_list = []

    # Leggi ogni CSV e aggiungilo alla lista
    for file in csv_files:
        df = pd.read_csv(file)
        df_list.append(df)

    # Unisci tutti i DataFrame
    combined_df = pd.concat(df_list, ignore_index=True)

    # Salva il CSV unito
    output_csv = "traffico_unito.csv"
    combined_df.to_csv(output_csv, index=False)

    print(f"Tutti i CSV uniti salvati in '{output_csv}'.")
