# GAN_tesi
## Dataset NSL-KDD
Per costruire dataset con feature uguali a quelle del dataset NSL-KDD, bisogna utilizzare innanzitutto nsl.py, che estrae feature da più pcap in modo parallelo (in caso di pcap troppo grandi divisi con editcap). Poi bisogna calcolare i flussi con calcolo_flowid e infine utilizzare etichette_traffico per etichettare i flussi in benevoli o malevoli.
## Dataset CICIDS-17
Per estrarre feature uguali al CICIDS17 bisogna installare il tool cicflowmeter con il seguente comando: pip install cicflowmeter; successivamente per l'estrazione delle feature bisogna utilizzare il seguente comando:
cicflowmeter -f esempio.pcap -c output_flows.csv
Poi viene etichettato il traffico con etichette_traffico.py e infine si utilizza lo script trasformazioneincids.py per avere feature coerenti con quelle del dataset e paper utilizzati.
