function quote(n) { return Math.round((n * 29 + 7) * 0.9); }
module.exports = quote;
if(require.main === module) console.log(JSON.stringify([quote(1),quote(4)]));
