from flask import Flask, render_template, request
import os
import requests
from math import sin, cos, sqrt, atan2, radians
import folium
from folium.plugins import AntPath, BeautifyIcon, MarkerCluster
from folium.plugins import BeautifyIcon, PolyLineTextPath

app = Flask(__name__)

def geolocaliser_adresse_ip(adresse_ip):
    url = f"https://ipapi.co/{adresse_ip}/json/"
    response = requests.get(url)
    data = response.json()

    return {
        "ip": adresse_ip,
        "pays": data.get("country_name"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
    }

def distance(lat1, lon1, lat2, lon2):
    R = 6371  # Rayon de la Terre en km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) * sin(dlat / 2) + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) * sin(dlon / 2)
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

def creer_carte_serveurs_messenger(selected_ips):
    carte = folium.Map(zoom_start=2)


    current_user_latitude = 50.5464
    current_user_longitude = 4.5351


    current_user_marker = folium.Marker(
        location=[current_user_latitude, current_user_longitude],
        tooltip="Current User",
        icon=folium.Icon(color="red")
    )
    current_user_marker.add_to(carte)


    marker_cluster = MarkerCluster().add_to(carte)

    locations = []
    for ip in selected_ips:
        info = geolocaliser_adresse_ip(ip)

        if info["latitude"] and info["longitude"]:
            marker = folium.Marker(
                location=[info["latitude"], info["longitude"]],
                tooltip=f"{info['ip']} - {info['pays']}",
            )
            marker.add_to(marker_cluster)
            locations.append([info["latitude"], info["longitude"]])


    for location in locations:
        lat1, lon1 = current_user_latitude, current_user_longitude
        lat2, lon2 = location
        dist = distance(lat1, lon1, lat2, lon2)
        dist_str = f"{dist:.2f} km"

        polyline = folium.PolyLine(
            locations=[[lat1, lon1], [lat2, lon2]],
            color="#7590ba",
            weight=2.5,
        )
        polyline.add_to(carte)

        polyline_text = PolyLineTextPath(
            polyline,
            dist_str,
            offset=-5,
            repeat=False,
            center=True,
            orientation="horizontal",
            fontsize=12,
            color="black",
        )
        polyline_text.add_to(carte)

    return carte

def creer_carte2(selected_ips2):
    carte = folium.Map(zoom_start=2)


    current_user_latitude = 50.5464
    current_user_longitude = 4.5351


    current_user_marker = folium.Marker(
        location=[current_user_latitude, current_user_longitude],
        tooltip="Current User",
        icon=folium.Icon(color="red")
    )
    current_user_marker.add_to(carte)


    marker_cluster = MarkerCluster().add_to(carte)



    locations = []
    for ip in selected_ips2:
        info = geolocaliser_adresse_ip(ip)

        if info["latitude"] and info["longitude"]:
            locations.append({
                "latitude": info["latitude"],
                "longitude": info["longitude"],
                "ip": info["ip"],
                "pays": info["pays"]
            })


    sorted_locations = sorted(locations, key=lambda x: (x["latitude"], x["longitude"]),reverse=True)



    for index, loc in enumerate(sorted_locations):
        marker = folium.Marker(
            location=[loc["latitude"], loc["longitude"]],
            tooltip=f"{loc['ip']} - {loc['pays']}",
            icon=BeautifyIcon(
                border_color="blue",
                text_color="blue",
                number=index + 1,
                inner_icon_style="margin-top:0;",
            ),
        )
        marker.add_to(marker_cluster)

        if index == 0:

            lat1, lon1 = current_user_latitude, current_user_longitude
            lat2, lon2 = loc["latitude"], loc["longitude"]
        else:

            lat1, lon1 = sorted_locations[index - 1]["latitude"], sorted_locations[index - 1]["longitude"]
            lat2, lon2 = loc["latitude"], loc["longitude"]

        dist = distance(lat1, lon1, lat2, lon2)
        dist_str = f"{dist:.2f} km"

        polyline = folium.PolyLine(
            locations=[[lat1, lon1], [lat2, lon2]],
            color="#7590ba",
            weight=2.5,
        )
        polyline.add_to(carte)

        polyline_text = PolyLineTextPath(
            polyline,
            dist_str,
            offset=-5,
            repeat=False,
            center=True,
            orientation="horizontal",
            fontsize=12,
            color="black",
        )
        polyline_text.add_to(carte)

    return carte





selected_ips2 = ["192.168.1.1","10.24.145.9","91.183.242.132","157.240.82.94","129.134.110.89","129.134.110.81","129.134.110.1","173.252.67.67","157.240.38.185","157.240.38.117","179.60.195.7"]

carte2 = creer_carte2(selected_ips2)
carte2.save("static/carte2.html")






@app.route('/', methods=['GET', 'POST'])
def index():
    domain_ip_pairs = [
        ("stun.c10r.facebook.com", "179.60.195.1"),
        ("edge-mqtt-shv-01-bru2.facebook.com", "179.60.195.6"),
        ("star.c10r.facebook.com", "179.60.195.7"),
        ("scontent.xx.fbcdn.net", "179.60.195.12"),
        ("star-mini.c10r.facebook.com", "179.60.195.36"),
        ("edge-turnservice-shv-01-bru2.facebook.com", "179.60.195.54"),
        ("edgeray-msgr-shv-01-bru2.facebook.com ", "179.60.195.128"),
        ("edgeray-msgr-shv-01-ams4.facebook.com", "157.240.201.57"),
        ("edgeray-msgr-shv-01-ams2.facebook.com ", "157.240.247.57"),
    ]

    if request.method == 'POST':
        selected_ips = request.form.getlist('ip_checkbox')
        carte = creer_carte_serveurs_messenger(selected_ips)

        if not os.path.exists('../static'):
            os.mkdir('../static')
        carte.save("static/carte_serveurs_messenger.html")


        return render_template('loca2.html', map=True, domain_ip_pairs=domain_ip_pairs,map2 = True)

    return render_template('loca2.html', map=False, domain_ip_pairs=domain_ip_pairs,map2 =True)

@app.route('/carte2', methods=['GET', 'POST'])
def carte2():

    carte2 = creer_carte2()

    if not os.path.exists('static'):
        os.mkdir('static')
    carte2.save("static/carte2.html")

    return render_template('loca2.html', map2=True)

if __name__ == '__main__':
        app.run(debug=True, port=5001)



