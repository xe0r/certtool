const fs = require('fs');

let content = fs.readFileSync('main.wasm');

let arr = new Uint8Array(content);
console.log(arr.length);

let res = 'const wasm_content = new Uint8Array([';


for (let x of arr) {
  res += x;
  res += ',';
}

res += ']);';
fs.writeFileSync('wasm-code.js', res);
