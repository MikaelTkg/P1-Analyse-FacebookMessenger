import pyshark
import numpy as np
from matplotlib import pyplot as plt

path1 = "Packets Messenger/APP_WIFI_photo_1min_JP_Mika_Messenger_final.pcapng"
path2 = "Packets Messenger/APP_WIFI_txt_1min_JP_Mika_Messenger_final.pcapng"
path3 = "Packets Messenger/APP_WIFI_appel_vocal_Mika_1min_Messenger.pcapng"
path4 = "Packets Messenger/APP_WIFI_appel_video_Mika_1min_Messenger.pcapng"
def extract_data_volume(pcap_file, bin_size=1):
    cap = pyshark.FileCapture(pcap_file)
    volume_bins = {}

    for packet in cap:
        if hasattr(packet, 'frame_info'):
            timestamp = float(packet.frame_info.time_epoch)
            bin_start = int(timestamp // bin_size) * bin_size
            packet_size = int(packet.frame_info.len) / 1024  # Convert to KB

            if bin_start in volume_bins:
                volume_bins[bin_start] += packet_size
            else:
                volume_bins[bin_start] = packet_size

    return volume_bins

def plot_multiple_data_volumes(volume_bins_list, titles, bin_size=1):
    if len(volume_bins_list) != len(titles):
        raise ValueError("The number of titles must match the number of datasets")

    num_graphs = len(volume_bins_list)
    num_rows = num_cols = int(np.ceil(np.sqrt(num_graphs)))

    fig, axs = plt.subplots(num_rows, num_cols, figsize=(12, 8))

    for idx, (volume_bins, title) in enumerate(zip(volume_bins_list, titles)):
        x = list(volume_bins.keys())
        y = [volume / bin_size for volume in volume_bins.values()]
        mean_value = np.mean(y)

        row = idx // num_cols
        col = idx % num_cols

        axs[row, col].plot(x, y, label='Volume de donnée')
        axs[row, col].axhline(mean_value, color='r', linestyle='--', label=f'Moyenne: {mean_value:.2f} KB/s')
        axs[row, col].set_xlabel('Temps (secondes)')
        axs[row, col].set_ylabel('Volume de donnée (KB/s)')
        axs[row, col].set_title(title)
        axs[row, col].legend()
        axs[row, col].set_ylim(0, 260)

    plt.tight_layout()
    plt.savefig('graphs_volume_donee.pdf')
    plt.show()



bin_size = 1  # Ajustez la taille des intervalles en secondes pour modifier la granularité du graphique

volume_bins1 = extract_data_volume(path1, bin_size)
volume_bins2 = extract_data_volume(path2, bin_size)
volume_bins3 = extract_data_volume(path3, bin_size)
volume_bins4 = extract_data_volume(path4, bin_size)

titles = [
    "Volume de donnée pour les photos ",
    "Volume de donnée pour les textes ",
    "Volume de donnée pour les appels vocaux",
    "Volume de donnée pour les appels vidéo",
]

plot_multiple_data_volumes([volume_bins1, volume_bins2, volume_bins3, volume_bins4], titles, bin_size)


