var iv = CryptoJS.enc.Base64.parse(document.getElementById("iv").innerHTML);
var ciphertext = CryptoJS.enc.Base64.parse(document.getElementById("encrypted").innerHTML);
var key = CryptoJS.enc.Hex.parse(sessionStorage.getItem("sharedKey"));
var decrypted = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, {iv: iv});

document.getElementById("encrypted").innerHTML = decrypted.toString(CryptoJS.enc.Utf8);
document.getElementById("iv").innerHTML = '';



