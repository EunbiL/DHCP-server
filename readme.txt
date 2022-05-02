ROUTAGE
Projet DHCP
N.DERRADJI - E.LEE


Dans notre code il y a 3 grandes parties:

1) ----Class DHSERVER----
C'est pour établir le serveur DHCP

-On commence avec le protocol UDP en utilisant la fonction SOCKET.

-Dans la boucle While: On attend les messages DISCOVER et REQUEST du client.
   - dhcpoptions = self.packet_analyzer(packet)[13]  ---> Pour récuperer les options du paquet reçu
   - dhcpMessageType = dhcpoptions[2]   ---> C'est le type du message reçu
   - Server Methods:
        def packet_analyzer(self, packet);   ---> Cette méthode sert à récuperer le message Discover d'un client
        def set_dhoffer(self, xid, ciaddr, chaddr, magicookie, ip); ---> C'est le paquet du serveur DHCP pour envoyer le message Offer au client.
        def set_dhack(self, xid, ciaddr, chaddr, magicookie, ip); ---> C'est le paquet du serveur DHCP pour envoyer le message ACK au client.



2) -----Class IPConvert----
Pour convertir les paquets d'héxadécimal en décimal ou en caractères.

Ce sont les paramètres avec lesquelles le serveur doit être rendu configurable.

-Method SET:
   -def IPadd(self, ip, mac_address); ---> Fait le lien entre l'adresse IP et l'adresse MAC.
   -def IPupdate(self, ip, mac_address); ---> Pour decrémenter le compteur d'adresses disponibles.
   -def BROADCASTaddr_get(self); ---> Pour renvoyer l'adresse Broadcast
   -def IP_get(self, ip, mac_address);
      for cle, valeur in self.list.items() :    ----> Pour vérifier que le client ne possède pas déjà d'adresse IP. 
          if(valeur == mac_address):
              return cle                       ----> Si oui,  on retourne l'adresse IP qui lui a été précédement attribué.
   -def IP_free_get(self): 
      for cle, valeur in self.list.items() :  ----> Pour chercher une adresse IP disponible
          if(valeur == "null"):        ----> On retourne l'adresse libre trouvée
             return cle
      return False                 ----> S'il n'y a plus d'adresses disponibles on renvoie False

           


3) -----__main__-----
Pour démarrer le serveur DHCP

On va ouvrir notre CONFIG_FILE en utilisant la librairie json.