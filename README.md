## Aufgabenstellung

Im Anhang zur Uebungsangabe findest du eine mit OpenPGP verschluesselte E-Mail, und unter http://exercises.itsi.rocks:5000/ einen Pseudo E-Mail Client, der hochgeladene E-Mails entschluesselt und anzeigt.

Deine Aufgabe ist es nun, die gegebene E-Mail so zu manipulieren, dass beim Oeffnen der E-Mails mit einem HTML-faehigen Client dieser geheime Inhalte aus der Mail unverschluesselt an einen beliebigen Server verschickt.

Die verwendete (alte) OpenPGP-Implementierung verschluesselt nur und verwendet keine MAC/Signatur, daher ist ein Angriff wie Efail moeglich.
Vorgehensweise:

- Lies dir die Funktionsweise von Efail durch
- Manipuliere die E-Mails zunaechst so, dass der erste Block nach dem Entschluesseln nur aus 0x00 besteht
- Erzeuge darauf hin einen entschluesselten ersten Block mit beliebigem Inhalt
- Versuche, beliebige Inhalte auch innerhalb der entschluesselten Mail zu erzeugen
- Schleuse HTML-Code so ein, dass er Teile der Nachricht exfiltriert.

### Hints

- Die verwendete Blockgroesse ist 16 Byte
- Der verschluesselte Block besteht aus aus dem IV am Beginn und danach dem eigentlichen Ciphertext und ist Base64 encodet.
- Anzeigen von byte-Arrays in python

```pythom
from binascii import *

foo = b'\x23\x45\x23'
print(hexlify(foo,' ',2)
```

XOR-Verknuepfen zweier Byte-Arrays

`result = bytes(a ^ b for a, b in zip(array1, array2))`

- Verwendet man formatierten Text in E-Mails (HTML), so wird ueblicherweise ein Message Part mit dem Content-Type multipart/alternative erzeugt. Dieser beinhaltet dann die Nachricht als Plain Text und als HTML Dokument

