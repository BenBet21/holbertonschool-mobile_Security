# Dynamic Analysis in Mobile Security — Task 3
## Revealing Hidden Functions

**Étudiant :** Benoît (benbet21cyber)
**Référence pédagogique :** Marc Chevalier — Holberton School
**Repo :** holbertonschool-mobile_Security — dynamic_analysis_in_mobile_security

---

## Cible

| | |
|---|---|
| APK fourni | `task3_d.apk` |
| SHA256 | `9577be7237d1d8e8d633143feca3df07ca8bc743d46d2459a6579659f81c846c` |
| Package installé (réel) | `com.holberton.task4_d` |
| Classe cible | `MainActivityKt` (fonction top-level Kotlin) |
| Méthode cachée | `aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(Function1<String, Unit>)` |
| Outils | jadx, Frida 17.17.0, ADB, Python 3 |

---

## 1. Objectif

L'application cible contient une fonction Kotlin délibérément jamais appelée par le
flux d'exécution normal, chargée de décoder un flag (Base64 + transformation
personnalisée). Objectif : la localiser statiquement, l'invoquer dynamiquement via
Frida sans modifier le code source, puis comprendre et reproduire son mécanisme
d'encodage.

## 2. Vérification d'intégrité et décompilation

```bash
$ sha256sum task3_d.apk
9577be7237d1d8e8d633143feca3df07ca8bc743d46d2459a6579659f81c846c  task3_d.apk
```

Hash confirmé identique à celui fourni. Décompilation avec jadx (chemin absolu
obligatoire) :

```bash
$ jadx -d ~/Downloads/task3_jadx_out ~/Downloads/task3_d.apk
INFO  - loading ...
INFO  - processing ...
ERROR - finished with errors, count: 190
```

Les 190 erreurs concernent des dépendances tierces (Jetpack Compose, Guava) et
n'empêchent pas l'exploitation des sources (`sources/`, `resources/` bien générés).

### 2.1 Identification du vrai package

Le nom de fichier `task3_d.apk` ne correspond pas au package réel : c'est
**`com.holberton.task4_d`**, conforme au décalage systématique déjà observé sur les
tâches précédentes (`task1_d` → `com.holberton.task2_d`, etc.). Ce décalage a été
confirmé via l'`AndroidManifest.xml` décompilé plutôt que supposé depuis le nom de
fichier — une hypothèse fausse ici aurait provoqué une `ClassNotFoundException` au
moment du hook.

Le package applicatif ne contient que `MainActivity.java`, `MainActivityKt.java` et
le thème Compose : aucune classe séparée dédiée à un "secret helper", donc la
fonction cachée est nécessairement dans l'un de ces deux fichiers.

## 3. Identification statique de la fonction cachée

`MainActivity.java` : état Compose `decodedFlag` (vide par défaut) et une coroutine
`retrieveEncryptedData()` qui se contente d'exécuter un callback — pas de logique de
déchiffrement.

`MainActivityKt.java` : la fonction `Greeting()` affiche par défaut :

```
"Hmm it seems the interesting function is never called."
```

indice explicite laissé par le challenge. Une méthode top-level supplémentaire,
jamais référencée ailleurs :

```kotlin
private static final void aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(
    Function1<? super String, Unit> function1) {
  // décodage Base64 + transformation, puis function1.invoke(flag)
}
```

**Trois éléments confirment la cible :**
- Nom d'obfuscation évocateur (alphabet déguisé en identifiant).
- `private static`, jamais appelée dans `Greeting()`, `GreetingPreview()`,
  `onCreate()` ni `retrieveEncryptedData()`.
- Signature cohérente avec le message par défaut affiché à l'écran.

## 4. Mise en place de l'environnement dynamique

Réexport des variables de pont ADB réseau (non persistantes entre sessions Kali) :

```bash
$ export ANDROID_ADB_SERVER_ADDRESS=10.10.99.2
$ export ANDROID_ADB_SERVER_PORT=5037
$ adb devices
emulator-5554   device
```

Tentative de redéploiement de `frida-server`, échec révélateur :

```
Unable to start: Error binding to address 127.0.0.1:27042: Address already in use
```

> **Pourquoi ?** Ce message ne signale pas une erreur de configuration, mais qu'une
> instance de `frida-server` tournait déjà (session précédente non arrêtée
> proprement). Réflexe correct : vérifier via `frida-ps -U` avant de forcer un
> redémarrage, et utiliser `adb shell pkill frida-server` pour un arrêt propre si
> nécessaire.

```bash
$ frida-ps -U
PID  NAME
----  -----
```

Installation et lancement de l'app :

```bash
$ adb install ~/Downloads/task3_d.apk
$ adb shell am start -n com.holberton.task4_d/.MainActivity
$ frida-ps -U | grep -i task4
20580  task4_d
```

## 5. Invocation dynamique avec Frida

La méthode ciblée est `private static final` et attend un objet implémentant
l'interface Kotlin `Function1<String, Unit>`. Il faut implémenter cette interface à
la volée via `Java.registerClass`, instancier l'objet obtenu, puis le transmettre en
argument.

### 5.1 Première tentative — échec par timeout

```javascript
var Function1Impl = Java.registerClass({
  name: "com.holberton.task4_d.FridaCallback",
  implements: [Java.use("kotlin.jvm.functions.Function1").class],
  methods: { invoke: function (arg) { /* ... */ } }
});
```

```
$ frida -U -p 20580 -l hook_hidden_flag.js
[*] Script démarré, recherche de MainActivityKt...
Failed to load script: timeout was reached
```

### 5.2 Diagnostic isolé

Script minimal sans `registerClass` pour isoler la variable en cause :

```javascript
Java.perform(function () {
  var MainActivityKt = Java.use("com.holberton.task4_d.MainActivityKt");
  console.log("[*] Classe chargée : " + MainActivityKt);
});
```

Ce script passe sans erreur : le problème est bien localisé dans l'appel à
`Java.registerClass`, précisément le suffixe `.class` sur le wrapper Frida de
l'interface — `.class` renvoie un `java.lang.Class` brut, incompatible avec le
format attendu par `implements`.

### 5.3 Correction et exécution réussie

```javascript
Java.perform(function () {
    var MainActivityKt = Java.use("com.holberton.task4_d.MainActivityKt");

    var Function1Impl = Java.registerClass({
        name: "com.holberton.task4_d.FridaCallback",
        implements: [Java.use("kotlin.jvm.functions.Function1")],
        methods: {
            invoke: function (arg) {
                console.log("[+] Flag reçu via callback : " + arg);
                return null;
            }
        }
    });

    var callbackInstance = Function1Impl.$new();
    MainActivityKt.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(callbackInstance);
});
```

```
$ frida -U -p 20580 -l hook_hidden_flag_v2.js
[*] Java.perform OK
[*] Classe MainActivityKt chargée
[*] Classe callback enregistrée avec succès
[*] Instance callback créée, appel de la fonction cachée...
[+] Flag reçu via callback : Holberton{calling_uncalled_functions_is_now_known!}
[*] Appel terminé
```

> **SECOP** — Attacher Frida à un process déjà lancé (`-p <PID>`) plutôt que de
> relancer l'app (`-n`) évite de perdre un état applicatif potentiellement
> pertinent en investigation réelle, comme on éviterait de redémarrer une machine
> compromise avant d'avoir figé son état mémoire.

## 6. Compréhension et reproduction du mécanisme d'encodage

Chaîne Base64 brute embarquée dans l'APK :

```
8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX
```

Pour chaque octet décodé, à l'indice `i` :

```
temp   = byte ^ 19
temp2  = (((temp >> 2) | (temp << 6)) & 255) - (i * 3)     (mod 256)
char   = (temp2 * 183) % 256
```

Script de vérification :

```python
import base64

b64 = "8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX"
decoded_bytes = base64.b64decode(b64)

flag_chars = []
for i, value in enumerate(decoded_bytes):
    temp = value ^ 19
    temp2 = (((temp >> 2) | (temp << 6)) & 255) - (i * 3)
    temp2 = temp2 % 256
    char_code = (temp2 * 183) % 256
    flag_chars.append(chr(char_code))

print("".join(flag_chars))
```

```
$ python3 decode_flag.py
Holberton{calling_uncalled_functions_is_now_known!}
```

Résultat rigoureusement identique à celui obtenu via Frida : double validation
dynamique + statique du mécanisme (XOR à clé fixe, rotation binaire 8 bits,
décalage positionnel, multiplication modulaire).

## 7. Flag obtenu

```
Holberton{calling_uncalled_functions_is_now_known!}
```

## 8. Conclusion

Ce challenge illustre un pattern directement transposable au travail
SOC/SECOP : une fonction sensible peut exister dans un binaire sans jamais être
exercée par le flux d'exécution nominal, et rester pourtant parfaitement
invocable via instrumentation runtime (Frida) ou reverse manuel.

> **SECOP** — Le "code mort" n'est pas un non-problème en detection engineering :
> une fonction inatteignable par l'UI reste atteignable par instrumentation, comme
> une route API non documentée reste appelable si elle n'est pas désactivée
> côté serveur. L'énumération de méthodes jamais référencées dans le flux normal
> est une étape de triage à part entière sur des binaires suspectés malveillants.

Deux réflexes méthodologiques confirmés : ne jamais se fier au nom de fichier pour
déduire le package réel, et diagnostiquer une erreur (timeout, port déjà utilisé)
en isolant la variable en cause avant de corriger en bloc.