# Task 2 — Dynamic Analysis in Mobile Security

**Statut : BLOQUÉE — flag non obtenu.**

## Cible
- Fichier : `app-release-task2.apk`
- SHA256 : `f5f43fab06d1b06e2bc3c705ae7ad55194400207e456418f14510b6a2002396c`
- Package réel : `com.holberton.task3` (⚠️ décalage de nommage par rapport au fichier)
- Flag attendu : `Holberton{keystore_is_not_as_safe_as_u_think!}`

## Reconnaissance réseau
- `tcpdump` (capture native sur l'émulateur) : aucun trafic applicatif, uniquement du bruit ICMPv6.
- `mitmproxy` puis `Burp Suite` (listener `*:8080`, CA utilisateur installé sur l'émulateur) : aucune requête interceptée après plusieurs relances de l'app.
- `AndroidManifest.xml` : **pas de permission `INTERNET`**.
- Aucune classe réseau (OkHttp/Retrofit/HttpURLConnection/Socket) dans le code Java, le smali (`classes.dex` + `classes2.dex`), ni dans les strings brutes des deux dex.

**Conclusion réseau : l'app ne peut techniquement effectuer aucune requête. L'énoncé générique du module (interception HTTP via Burp/mitmproxy) ne s'applique pas à ce binaire.**

## Analyse statique (JADX + APKTool)
- Seul écran : `FibonacciDecryptionScreen` (`MainActivityKt.java`), lancé depuis `MainActivity.onCreate`.
- Logique observée :
  ```
  performslowDecryption() =
      xorDecrypt(Base64.decode(chaîne_chiffrée), key = String.valueOf(slowRecursive(150)))
  ```
- `slowRecursive()` : récursion naïve non mémoïsée du calcul de Fibonacci.
- Recherche exhaustive de "keystore" / du flag : **aucun résultat** dans le code Java, le smali, `res/values/strings.xml`, les strings des `.dex`, ni `assets/`.

## Anomalies techniques identifiées
1. `slowRecursive` retourne un `long` Java (64 bits signés). `Fibonacci(150)` réel (~9,97×10³⁰) dépasse très largement la capacité d'un `long` (~9,22×10¹⁸) → **overflow silencieux**.
   - Valeur réelle attendue côté Java après overflow : `6792540214324356296`.
   - Testée comme clé XOR : résultat toujours illisible, ne correspond pas au flag.
2. En récursion naïve pure, `slowRecursive(150)` nécessite ~2¹⁵⁰ appels — **mathématiquement infaisable** en temps humain. Ce chemin de code ne peut jamais aboutir en pratique sur un device réel.

## Hypothèse retenue
`FibonacciDecryptionScreen` / `performslowDecryption` semblent être soit du code leurre, soit appartenir à un binaire ne correspondant pas au challenge visé (thème « keystore »). Aucune preuve dans le fichier fourni ne permet d'atteindre `Holberton{keystore_is_not_as_safe_as_u_think!}`.

## Prochaines étapes
- Si un APK corrigé est fourni, reprendre la reconnaissance réseau (tcpdump) avant de repartir en analyse statique.