from base64 import encode
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QTextEdit, QMessageBox
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

def generateKeys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def encryptMsg(publicKey, valHash1):
    keyToEncrypt = RSA.import_key(publicKey)
    cipher = PKCS1_OAEP.new(keyToEncrypt)
    encryptedHash = cipher.encrypt(valHash1)
    return encryptedHash

def decryptMsg(privateKey, endcryptedHash):
    keyToDecrypt = RSA.import_key(privateKey)
    cipher = PKCS1_OAEP.new(keyToDecrypt)
    try:
        decryptedHash = cipher.decrypt(endcryptedHash)
    except:
        decryptedHash = bytes("Nie mozna odszyfrowac haszu z powodu zlego klucza", encoding='utf-8')
    return decryptedHash


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PODPIS CYFROWY")
        self.setFixedSize(1280,400)
        self.setStyleSheet("background-color: #F7F1E7;")
        self.widgets()
        self.privateKey1, self.publicKey1 = self.privateKey2, self.publicKey2 = generateKeys()  
        
    def widgets(self):
        self.lbl0 = QLabel("<b>   PODPIS \n CYFROWY </b>", self)
        self.lbl1 = QLabel("Wyslana wiadomosc", self)
        self.lbl2 = QLabel("Odebrana wiadomosc", self)
        self.lbl3 = QLabel(self)
        self.lbl4 = QLabel(self)
        self.lbl5 = QLabel(self)
        self.lbl6 = QLabel(self)
        self.lbl8 = QLabel(self)
        self.lbl7 = QLabel(self)

        self.lbl0.setGeometry(45,8,150,50)
        self.lbl1.setGeometry(420,70,1000,20)
        self.lbl2.setGeometry(920,70,1000,20)

        
        btn1 = QPushButton("OBLICZ \n HASZ",self)
        btn1.clicked.connect(self.calcHashButton)
        btn2 = QPushButton("GENERUJ NOWA PARE \n KLUCZY DLA WYSLANEJ \n WIADOMOSCI",self)
        btn2.clicked.connect(self.newKeyPair1)
        btn3 = QPushButton("RESET",self)
        btn3.clicked.connect(self.reset)
        btn4 = QPushButton("EKSPORTUJ WYNIKI \n DO .TXT",self)
        btn4.clicked.connect(self.exportResult)

        btn1.setGeometry(20,70,150,60)
        btn2.setGeometry(20,150,150,60)
        btn3.setGeometry(20,230,150,60)
        btn4.setGeometry(20,310,150,60)

        self.msgA = QTextEdit(self)
        self.msgA.setPlaceholderText("Wprowadz wyslana wiadomosc(Nr1)")
        self.msgA.setGeometry(210,120,500,200)
        self.msgB = QTextEdit(self)
        self.msgB.setPlaceholderText("Wprowadz odebrana wiadomosc(Nr2)")
        self.msgB.setGeometry(740,120,500,200)

    def calcHashButton(self):
        temp1 = "Hasz z wyslanej wiadomosci A: "
        temp2 = "Hasz z odebranej wiadomosci B: "
        temp3 = "Hasz z odszyfrowanej wyslanej wiadomosci: "
        temp5 = "Czy hashe wiadomosci sa takie same? "
        
        hash1 = SHA256.new()
        hash2 = SHA256.new()
        hash1.update(bytes(self.msgA.toPlainText(), encoding="utf-8"))
        hash2.update(bytes(self.msgB.toPlainText(), encoding="utf-8"))
        valHash1 = hash1.hexdigest()
        valHash2 = hash2.hexdigest() 

        self.lbl4.setText(temp1 + hash1.hexdigest())
        self.lbl5.setText(temp2 + hash2.hexdigest())

        encryptedHash = encryptMsg(self.publicKey1.export_key(), bytes(valHash1, encoding='utf-8'))
        decryptedHash = decryptMsg(self.privateKey2.export_key(), encryptedHash).decode("utf-8")
        self.lbl6.setText(temp3 + decryptedHash)

        isSame = False
        if(valHash2 == decryptedHash):
            isSame = True
        self.lbl7.setText(temp5 + str(isSame))

        self.lbl8.setText("Czy klucze sa sparowane? True");

        popMsg = QMessageBox()
        popMsg.setWindowTitle("Wyniki")
        popMsg.setText(str(self.lbl4.text()) + "\n" + str(self.lbl5.text()) + "\n" + str(self.lbl6.text()) + "\n" + self.lbl7.text() + "\n" + self.lbl8.text())
        popMsg.exec()

    def newKeyPair1(self):
        self.paired = False
        self.lbl8.setText("Czy klucze sa sparowane? " + str(self.paired))
        self.privateKey2, self.publicKey2 = generateKeys()
        popMsg = QMessageBox()
        popMsg.setWindowTitle("Wyniki po nowej parze kluczy")
        popMsg.setText(str(self.lbl4.text()) + "\n" + str(self.lbl5.text()) + "\n" + str(self.lbl6.text()) + "\n" + self.lbl7.text() + "\n" + self.lbl8.text())
        popMsg.exec()

        
    def reset(self):
        self.msgA.clear();
        self.msgB.clear();

    def exportResult(self):
        popMsg = QMessageBox()
        popMsg.setWindowTitle("Eksport")
        popMsg.setText("Wyniki zostaly wyeksportowane do pliku Wyniki.txt!      \n")
        popMsg.exec()
        with open('Wyniki.txt','w') as f:
            f.write("Wiadomosc A: " + str(self.msgA.toPlainText() + "\n"))
            f.write("Wiadomosc B: " + str(self.msgB.toPlainText() + "\n"))
            f.write(str(self.lbl4.text() + "\n"))
            f.write(str(self.lbl5.text() + "\n"))
            f.write(str(self.lbl6.text() + "\n"))
            f.write(str(self.lbl7.text()))

app = QApplication([])
window = Window()
window.show()
sys.exit(app.exec())
