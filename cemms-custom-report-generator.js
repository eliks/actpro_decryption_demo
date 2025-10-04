const crypto = require('crypto');
const fs = require('fs');
const mrz = require('mrz'); //npm install mrz
const { formartSortDate, getCountryName, readCsv } = require('./utils.js')
const privateKey = fs.readFileSync('private_key.pem', 'utf8');
const COUNTRY_OF_DESTINATION = "Philippines";
const filePath = "CL_CSV_20250930015834_SOL_PH_PII.csv";
var iv = Buffer.alloc(16);

(async () => {
  const cLrows = await readCsv(filePath);
  var clDataRowsMap = cLrows.map(row => { return { "iCol": row[8], "jCol": String(row[9]).padStart(6, "0"), "bpiCol": row[1776], "bpjCol": row[1777] } });
  var clDataRows = [];
  clDataRowsMap.forEach((e, index) => {
    var BpjBuffer = Buffer.from(e.bpjCol, 'base64');
    var BpiBuffer = Buffer.from(e.bpiCol, 'base64');
    var sessionKey = rsaDecryptSessionKey(Buffer.from(BpjBuffer, 'base64'), privateKey);
    iv.write(String(e.iCol) + e.jCol, 0, 16, 'utf8');
    var mrzDecrypt = decryptAes256Cbc(BpiBuffer, iv, sessionKey);
    let mrzDecryptStr = mrzDecrypt.toString('utf8')
    var mrzDecryptSplit = mrzDecryptStr.split('|');
    let mrzFull = mrzDecryptSplit[4].split(':')[1];
    let mrzLines = [mrzFull.slice(0, 44), mrzFull.slice(44, 88)];
    let mrzObj = mrz.parse(mrzLines);
    let fullName = mrzDecryptSplit[5].split(':')[1];

    let mrzDecryptObj = {
      "EXPIRE_DATE": formartSortDate(mrzObj.fields.expirationDate),
      "ID_NUMBER": mrzObj.fields.documentNumber,
      "CELIENT_FULL_NAME": fullName,
      "CLIENT_SURNAME": mrzObj.fields.lastName,
      "CLIENT_FIRST_NAME": mrzObj.fields.firstName,
      "DOB": formartSortDate(mrzObj.fields.birthDate),
      "COUNTRY_OF_DESTINATION": COUNTRY_OF_DESTINATION,
      "CLIENT_ADDRESS": getCountryName(mrzObj.fields.nationality),
      "MRZ": mrzFull
    };
    clDataRows.push(mrzDecryptObj);
  });
  console.log(clDataRows);
})();

function decryptAes256Cbc(ciphertext, iv, key) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let mrzPlainText = decipher.update(ciphertext);
  mrzPlainText = Buffer.concat([mrzPlainText, decipher.final()]);
  return mrzPlainText;
};

function rsaDecryptSessionKey(encryptedKey, privateKey) {
  try {
    const decryptedkey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      encryptedKey
    );
    return decryptedkey;
  } catch (err) {
    throw new Error("RSA decryption failed: invalid key or BPJ data.");
  }
};

