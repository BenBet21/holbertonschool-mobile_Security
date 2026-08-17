# Dynamic Analysis in Mobile Security — Task 1
## Hooking Native Functions in Android

**Holberton School — Spécialisation Cybersécurité**
**Repo :** `holbertonschool-mobile_Security`
**Directory :** `dynamic_analysis_in_mobile_security`
**Fichiers :** `1-flag.txt`, `1-report.md`

---

## 1. Objectif

Retrouver un flag traité côté code natif (JNI) mais jamais affiché dans l'interface de l'application, en hookant dynamiquement la méthode native `getSecretMessage` avec Frida.

**APK cible :** `task1_d.apk`
**Package installé (vérifié à l'exécution) :** `com.holberton.task2_d`
**Classe cible :** `MainActivity`
**Méthode cible :** `getSecretMessage()`
**Bibliothèque native :** `libnative-lib.so`

---

## 2. Prérequis

Environnement identique à la Task 0 : Frida opérationnel (frida-tools côté Kali, frida-server déployé en root sur l'émulateur Android distant), ADB connecté à l'émulateur via VPN infra (`10.10.99.2`), APK installé et application lancée.

---

## 3. Analyse statique préalable

### 3.1 Identification de la bibliothèque native

Extraction rapide de la liste des bibliothèques embarquées dans l'APK, sans décompression complète :

```
cd ~/Downloads
unzip -l task1_d.apk | grep "\.so"
```

Résultat :

```
lib/arm64-v8a/libnative-lib.so
lib/x86_64/libnative-lib.so
lib/armeabi-v7a/libnative-lib.so
lib/x86/libnative-lib.so
```

La bibliothèque native est présente pour les quatre ABI. L'émulateur ciblé tournant en `x86_64`, c'est `lib/x86_64/libnative-lib.so` qui est chargée en mémoire à l'exécution.

### 3.2 Décompilation du DEX (JADX)

```
jadx -d ~/Downloads/task1_jadx_out ~/Downloads/task1_d.apk
```

Lecture de `MainActivity.java` :

```java
public final native String getSecretMessage();

static {
    System.loadLibrary("native-lib");
}
```

Deux informations clés :

- `getSecretMessage()` est déclarée **`native`** : son implémentation réelle vit dans `libnative-lib.so`, pas dans le bytecode Java.
- Le chargement de la bibliothèque native se fait via `System.loadLibrary("native-lib")`, dans le bloc d'initialisation statique de la classe.

La déclaration `native` étant explicite (pas de `registerNatives` dynamique observé), le lien Java ↔ natif est visible statiquement — ce qui oriente la stratégie de hook vers un hook Java direct plutôt qu'un hook par adresse mémoire.

---

## 4. Reconnaissance dynamique — observation du comportement affiché

Lancement de l'application et clic sur le bouton **"Generate String"** : l'interface affiche une chaîne illisible (résultat binaire non décodé), confirmant qu'un traitement — natif ici — produit une donnée qui n'est pas exposée en clair à l'utilisateur.

---

## 5. Hooking de la méthode native avec Frida

### 5.1 Résolution du nom de package réel

Le nom de package lu en statique (`com.holberton.task1_d`) ne correspond pas au process réellement exécuté. Une première tentative de hook a échoué :

```
Error: java.lang.ClassNotFoundException: Didn't find class "com.holberton.task1_d.MainActivity"
```

Vérification du nom de process réellement actif :

```
frida-ps -U
```

Résultat : `task2_d` — le package effectivement installé est `com.holberton.task2_d`.

Confirmation du nom de classe exact via énumération des classes chargées en mémoire :

```javascript
// list_classes.js
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.toLowerCase().indexOf("mainactivity") !== -1) {
                console.log(className);
            }
        },
        onComplete: function () {
            console.log("[*] Recherche terminée");
        }
    });
});
```

```
frida -U -n task2_d -l list_classes.js
```

Résultat confirmant la classe cible : `com.holberton.task2_d.MainActivity`

### 5.2 Hook de `getSecretMessage()`

Un hook Java sur la méthode `native` suffit pour intercepter la valeur retournée par le code JNI, sans avoir besoin de résoudre l'adresse mémoire exacte dans `libnative-lib.so` :

```javascript
// hook_reco_task1.js
Java.perform(function () {
    var MainActivity = Java.use("com.holberton.task2_d.MainActivity");
    MainActivity.getSecretMessage.implementation = function () {
        var result = this.getSecretMessage();
        console.log("[*] getSecretMessage() a retourné : " + result);
        return result;
    };
    console.log("[*] Hook installé sur getSecretMessage");
});
```

Exécution, attaché au process déjà lancé :

```
frida -U -n task2_d -l hook_reco_task1.js
```

Puis déclenchement du bouton **"Generate String"** dans l'application.

### 5.3 Résultat obtenu

```
Attaching...
[*] Hook installé sur getSecretMessage
[Android Emulator 5554::task2_d ]-> [*] getSecretMessage() a retourné : Holberton{native_hooking_is_no_different_at_all}
```

Le flag est intercepté en clair dès le retour de la fonction native, avant tout traitement d'affichage côté UI qui le rend illisible à l'écran.

---

## 6. Vérification complémentaire — symboles JNI exportés

Pour confirmer visuellement le lien entre la méthode Java et son implémentation native (convention de nommage JNI `Java_<package>_<Classe>_<méthode>`), listing des symboles exportés de la bibliothèque chargée par le process :

```
frida -U -n task2_d -i
```

Le symbole `Java_com_holberton_task2_d_MainActivity_getSecretMessage` apparaît dans `libnative-lib.so`, confirmant que le lien Java ↔ natif suit la convention JNI standard — pas de `registerNatives` dynamique ici, ce qui explique pourquoi un hook Java simple (`Java.use()` + `.implementation`) a suffi sans recourir à `Interceptor.attach()` sur une adresse mémoire.

---

## 7. Flag extrait

```
Holberton{native_hooking_is_no_different_at_all}
```

---

## 8. Conclusion

Cette tâche illustre un point méthodologique central du module : **hooker une méthode Java déclarée `native` intercepte tout aussi bien la sortie du code JNI que de hooker directement l'adresse native avec `Interceptor.attach()`**, tant que le lien Java ↔ natif est déclaré statiquement (et non enregistré dynamiquement via `registerNatives`). L'approche par adresse mémoire (`Interceptor.attach()`, avec `onEnter`/`onLeave` sur les registres) reste indispensable dès que ce lien statique n'existe pas — c'est elle qu'il faudrait mobiliser face à un JNI obfusqué ou enregistré dynamiquement.
