import pandas as pd
import os

#file da etichettare
input_csv = "flows_with_features.csv"

df = pd.read_csv(input_csv)
#etichetta come malevolo se il porto destinazione o sorgente è 9
df['target'] = ((df['dst_port'] == 9) | (df['src_port'] == 9)).astype(int)

base, ext = os.path.splitext(input_csv)
output_csv = f"{base}_labeled{ext}"

# Salva il CSV risultante
df.to_csv(output_csv, index=False)

print(f"CSV elaborato salvato in {output_csv}")
