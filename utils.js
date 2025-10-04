const csv = require('csv-parser');
const fs = require('fs');
const { parse, format } = require('date-fns'); //npm install date-fns
const countries = require('i18n-iso-countries'); //npm install i18n-iso-countries

function formartSortDate(dateStr) {
    var parsedDate = parse(dateStr, 'yyMMdd', new Date());
    var formattedDate = format(parsedDate, 'yyyy-MM-dd');
    return formattedDate;
};

function getCountryName(alpha3) {
    // Load English names (required)
    countries.registerLocale(require("i18n-iso-countries/langs/en.json"));
    const alpha2 = countries.alpha3ToAlpha2(alpha3);
    const countryFullName = countries.getName(alpha2, "en");
    return countryFullName;
};

async function readCsv(filePath) {
    return new Promise((resolve, reject) => {
        const results = [];

        fs.createReadStream(filePath)
            .pipe(csv({
                headers: false,
            }))
            .on('data', (row) => {
                const renamedRow = {};
                Object.keys(row).forEach((key, index) => {
                    renamedRow[index] = String(row[key]);
                });
                results.push(renamedRow);
            })
            .on('end', () => resolve(results))
            .on('error', (error) => {
                reject(error);
            });
    });
};

module.exports = {
    formartSortDate,
    getCountryName,
    readCsv
}