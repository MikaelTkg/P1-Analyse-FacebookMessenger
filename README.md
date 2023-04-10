CarteMessenger

CarteMessenger est une application Flask qui permet de visualiser les serveurs Messenger et leurs distances par rapport à un utilisateur.
 L'application utilise des bibliothèques telles que Geopy, Folium et Requests pour obtenir des informations de localisation et créer des cartes interactives.

°Installation

Assurez-vous d'avoir Python 3.6 ou une version ultérieure installée sur votre système.
Installez les dépendances nécessaires en exécutant la commande suivante :
--> pip install -r requirements.txt

°Utilisation
Exécutez le script principal loca_2.py en utilisant la commande suivante :

python loca_2.py
Ouvrez votre navigateur et accédez à l'adresse http://127.0.0.1:5001/ pour voir l'application en action.

°Fonctionnalités
Visualisation des serveurs Messenger et de leurs distances par rapport à un utilisateur sur une carte interactive.
Affichage d'informations supplémentaires telles que les adresses IP et les noms de pays pour chaque serveur.
Possibilité de sélectionner et de désélectionner les serveurs pour les afficher sur la carte.


°Bibliothèques utilisées
Flask : Pour créer l'application web.
Geopy : Pour obtenir des informations de géolocalisation à partir d'adresses IP.
Folium : Pour créer des cartes interactives avec des marqueurs et des lignes.
Requests : Pour effectuer des requêtes HTTP et récupérer des données de localisation.

°Licence
Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.