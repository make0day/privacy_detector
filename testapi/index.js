const express = require('express')
const app = express()
const port = 3000
const fs = require('fs');
const fl = fs.readdirSync('./jsons');
var ct = 0

fl.forEach(fn => {
    ct++
    var path = '/api/' + ct;
    app.get(path,(req,res) => {
        const jsonFile = fs.readFileSync('./jsons/'+fn);
        const jsonData = JSON.parse(jsonFile);
        res.json(jsonData)    
    })
})

app.listen(port,ct, () => {
  console.log(`Open ${ct} Apis`)
  console.log(`Example app listening at http://localhost:${port}/api/{num}`)
})