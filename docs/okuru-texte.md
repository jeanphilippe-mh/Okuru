# Copie texte du journal Okuru

`okuru.service` conserve ses sorties dans le namespace journald `okuru` et demande le démarrage de `okuru-texte.service`. Cette unité distincte ajoute les messages complets à `/var/log/okuru.log` et enregistre sa progression dans `/var/lib/okuru-texte`. Elle n'arrête pas Okuru si elle échoue. Ses diagnostics sont consultables avec `sudo journalctl -u okuru-texte.service`.

Le service de copie détecte le remplacement du fichier après rotation et rouvre le nouveau à la prochaine entrée. La règle logrotate fournie par l'administrateur, avec `create 0640 freebox freebox` et `delaycompress`, ne nécessite pas de `postrotate` pour ce miroir. Aucun fichier de configuration logrotate n'est installé ou modifié. Un message écrit au moment précis du renommage peut encore apparaître dans l'archive précédente. L'intégration avec cette règle doit être testée sur la VM.

## Avant la première activation

Vérifier la configuration réellement installée, le fichier existant et son propriétaire :

```sh
sudo systemctl cat okuru.service
sudo ls -l /var/log/okuru.log
sudo cat /etc/logrotate.d/okuru
```

Au premier lancement, si le curseur n'existe pas encore, le service exige un fichier vide ; il refuse un fichier non vide pour ne pas mélanger l'historique existant à un nouvel import et créer des doublons silencieux. **Conserver ou archiver l'ancien fichier avant de le vider ou de le remplacer** : aucune donnée n'est supprimée par l'installation. Le fichier doit déjà exister, être un fichier ordinaire sans lien supplémentaire et respecter soit `root:root` avec le mode `0600`, soit `freebox:freebox` avec le mode `0640`.

Pour une **première installation uniquement**, la commande suivante vérifie que les sorties actuelles vont bien à journald, refuse de supprimer un curseur existant, arrête les deux services de copie connus s'ils fonctionnent, déplace les anciens fichiers texte vers une sauvegarde privée, puis crée le nouveau fichier vide sans écraser de fichier existant. Elle ne touche pas aux fichiers `.journal`. Vérifier au préalable qu'aucun autre processus ne conserve `/var/log/okuru.log` ouvert et qu'aucune rotation n'est en cours.

```sh
sudo sh -eu <<'SH'
umask 077
test "$(systemctl show okuru.service -p StandardOutput --value)" = journal
test "$(systemctl show okuru.service -p StandardError --value)" = journal
test "$(systemctl show okuru.service -p LogNamespace --value)" = okuru
if [ -e /var/lib/okuru-texte/cursor ] || [ -L /var/lib/okuru-texte/cursor ]; then
    echo 'Curseur existant : nettoyage interrompu, vérifier la situation.' >&2
    exit 1
fi
for unit in okuru-texte.service okuru-journal-mirror.service; do
    if systemctl is-active --quiet "$unit"; then systemctl stop "$unit"; fi
done
for file in /var/log/okuru.log*; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    if [ -L "$file" ] || [ ! -f "$file" ]; then
        echo "Fichier inattendu : $file ; nettoyage interrompu." >&2
        exit 1
    fi
done
backup_dir=$(mktemp -d /var/backups/okuru-journaux.XXXXXXXX)
echo "Sauvegarde des anciens fichiers : $backup_dir"
for file in /var/log/okuru.log*; do
    [ -e "$file" ] || continue
    mv -- "$file" "$backup_dir/"
done
set -C
: > /var/log/okuru.log
ls -l /var/log/okuru.log
SH
```

La sauvegarde est protégée par le répertoire privé et n'est pas effacée ; elle ne libère pas nécessairement de place. Le nouveau fichier est créé `root:root` en `0600`. Au premier lancement, le miroir réimporte les messages encore conservés dans journald : le nouveau fichier ne restera pas vide. Une erreur pendant la sauvegarde interrompt la commande ; les fichiers déjà déplacés restent dans le répertoire affiché.

Après la première rotation, les permissions sont celles de la règle logrotate existante. Le compte `freebox` peut écrire dans un fichier dont il est propriétaire ; vérifier les droits d'accès attendus, y compris pour Monit et les archives. N'effacez pas le curseur pour résoudre un problème sans avoir d'abord vérifié son état et sauvegardé les fichiers : cela peut provoquer un nouvel import.

## Installation

Depuis une copie de ce dépôt sur la VM, après examen des unités déjà installées et de l'espace disponible :

```sh
sudo systemctl cat okuru-texte.service
sudo systemctl status okuru-journal-mirror.service
```

Une unité absente est signalée comme introuvable. Ne pas faire fonctionner simultanément une autre copie vers le même fichier. Installer le programme et l'unité, puis ajouter la dépendance au service Okuru sans écraser ses adaptations locales :

```sh
sudo install -d -m 0755 /usr/local/libexec/okuru
sudo install -m 0755 scripts/okuru-journal-mirror.py /usr/local/libexec/okuru/okuru-journal-mirror.py
sudo install -m 0644 deploy/systemd/okuru-texte.service /etc/systemd/system/okuru-texte.service
sudo systemctl edit okuru.service
```

Dans l'éditeur, ajouter :

```ini
[Unit]
Wants=okuru-texte.service
```

Puis activer la copie et vérifier son état :

```sh
sudo systemctl daemon-reload
sudo systemctl reset-failed okuru-texte.service
sudo systemctl restart okuru-texte.service
sudo systemctl status okuru-texte.service
sudo tail -F /var/log/okuru.log
```

Le redémarrage concerne seulement la copie : il ne redémarre pas Okuru. Au prochain démarrage d'Okuru, `Wants=` demandera également le démarrage de la copie. L'installation ci-dessus met à jour les fichiers de programme et d'unité de mêmes noms ; examiner et sauvegarder toute version locale différente avant de les remplacer. Elle ne modifie ni le journal existant, ni le curseur, ni la règle logrotate.

## Fonctionnement et limites

Le premier lancement lit les messages encore accessibles dans journald, puis suit les nouveaux. Le curseur persisté permet de reprendre normalement sans réimporter l'historique à chaque redémarrage ou rotation. Le champ `MESSAGE` est recopié complet, sans les métadonnées externes de journald ; les messages JSON restent en JSON.

Après une panne survenant entre l'écriture d'un message et l'enregistrement de son curseur, ce message peut être dupliqué au redémarrage ; une écriture interrompue peut laisser un fragment. Un arrêt prolongé, la rétention et les limites de débit de journald peuvent rendre des messages irrécupérables : un curseur périmé peut passer inaperçu. Les écritures synchronisées peuvent également provoquer un retard sous forte charge. Surveiller l'état de l'unité, les droits et l'espace disque : le fichier texte n'est pas compris dans le quota de journald.

La copie et sa rotation ne sont pas encore vérifiées avec systemd et logrotate réels sur la VM. La règle existante doit y être testée sans écraser ou supprimer les archives.
